/* (C) 2002 Milan Pikula */

#include <linux/medusa/l3/registry.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/init.h>
#include <linux/mount.h>
#include "../../../fs/mount.h"

#include "kobject_process.h"
#include "kobject_file.h"
#include <linux/medusa/l1/file_handlers.h>

/* the getfile event types (yes, there are more of them) are a bit special:
 * 1) they are called from the beginning of various access types to get the
 *    initial VS set,
 * 2) they gain some additional information, which enables L4 code to keep
 *    the file hierarchy, if it wants.
 * 3) due to creepy VFS design in Linux we sometimes do some magic.
 */

struct getfile_event {
	MEDUSA_ACCESS_HEADER;
	char filename[NAME_MAX+1];
};

MED_ATTRS(getfile_event) {
	MED_ATTR_RO (getfile_event, filename, "filename", MED_STRING),
	MED_ATTR_END
};
MED_EVTYPE(getfile_event, "getfile", file_kobject, "file",
		file_kobject, "parent");

/**
 * medusa_evocate_mnt - find the uppermost struct vfsmount for given dentry/inode.
 * @dentry: dentry to perform lookup on.
 *
 * This is a helper routine for file_kobj_validate_dentry. It does the black
 * magic to get the needed information, and owes for its existence to
 * the dirty design of VFS, where some parts of information are just missing.
 * From all possible vfsmounts, we must return the uppermost one to get
 * it right; and we try to avoid recursion 'cause we value the stack.
 */

struct vfsmount * medusa_evocate_mnt(struct dentry *dentry)
{
	int depth, last_depth, maxdepth, can_nest;
	struct mount * p;
	int count = 0;

	/* get the local root */
	//spin_lock(&dcache_lock);
	rcu_read_lock();
	while (!IS_ROOT(dentry))
		dentry = dentry->d_parent;
	dget(dentry);
	rcu_read_unlock();
	//spin_unlock(&dcache_lock);

	maxdepth = 0;
	do {
		can_nest = 0;
		last_depth = -1; depth = 0;

		/* hope that init isn't chrooted; get "global" root */
		spin_lock(&init_task.fs->lock);
		p = real_mount(init_task.fs->root.mnt);
		while (p->mnt_parent != p->mnt_parent->mnt_parent)
			p = p->mnt_parent;
		mntget(&p->mnt);
		spin_unlock(&init_task.fs->lock);

		//spin_lock(&dcache_lock);
		do {
			count++;
			if (depth == maxdepth) {
				if (p->mnt.mnt_root == dentry) {
					//spin_unlock(&dcache_lock);
					dput(dentry);
					return &p->mnt;
				}
				can_nest = can_nest || !list_empty(&(p->mnt_mounts));
			}
			if ((depth < maxdepth) && (last_depth <= depth) && !list_empty(&(p->mnt_mounts))) {

				mntput(&p->mnt);
				p = real_mount(mntget(&list_entry((p->mnt_mounts.next), struct mount, mnt_child)->mnt));
				last_depth = depth++;
				continue;

			}
			if (!list_empty(&(p->mnt_child)) && list_entry((p->mnt_child.next), struct mount, mnt_mounts) != p->mnt_parent) {

				mntput(&p->mnt);
				p = real_mount(mntget(&list_entry((p->mnt_child.next), struct mount, mnt_child)->mnt));
				last_depth = depth;
				continue;

			}

			mntput(&p->mnt);
			p = real_mount(mntget(&p->mnt_parent->mnt));
			last_depth = depth--;

		} while (depth >= 0);
		//spin_unlock(&dcache_lock);
		mntput(&p->mnt);
		maxdepth++;
	} while (can_nest);

	dput(dentry);
	printk("Fatal error: too drunk to evocate mnt. Returning init's mnt instead.\n");
	return mntget(init_task.fs->root.mnt);
}

static medusa_answer_t do_file_kobj_validate_dentry(struct nameidata * ndcurrent,
		struct nameidata * ndupper, struct nameidata * ndparent);

void medusa_clean_inode(struct inode * inode)
{
	INIT_MEDUSA_OBJECT_VARS(&inode_security(inode));
}
void medusa_get_upper_and_parent(struct nameidata * ndsource,
		struct nameidata * ndupperp, struct nameidata * ndparentp)
{
	*ndupperp = *ndsource;
	dget(ndupperp->path.dentry);
	if (ndupperp->path.mnt)
		mntget(ndupperp->path.mnt);
	else if (IS_ROOT(ndupperp->path.dentry))
		ndupperp->path.mnt = medusa_evocate_mnt(ndupperp->path.dentry); /* FIXME: may fail [?] */

	while (IS_ROOT(ndupperp->path.dentry)) {
		struct vfsmount * tmp;
		if (real_mount(ndupperp->path.mnt)->mnt_parent == real_mount(ndupperp->path.mnt)->mnt_parent->mnt_parent)
			break;
		dput(ndupperp->path.dentry);
		ndupperp->path.dentry = dget(real_mount(ndupperp->path.mnt)->mnt_mountpoint);
		tmp = mntget(&real_mount(ndupperp->path.mnt)->mnt_parent->mnt);
		mntput(ndupperp->path.mnt);
		ndupperp->path.mnt = tmp;
	}
	if (ndparentp) {
		if (IS_ROOT(ndupperp->path.dentry))
			*ndparentp = *ndsource;
		else {
			ndparentp->path.dentry = ndupperp->path.dentry->d_parent;
			ndparentp->path.mnt = ndupperp->path.mnt;
		}
		dget(ndparentp->path.dentry);
		if (ndparentp->path.mnt)
			mntget(ndparentp->path.mnt);
	}

	/* Now we have dentry and mnt. If IS_ROOT(dentry) then the dentry is global filesystem root */
	return;
}

void medusa_put_upper_and_parent(struct nameidata * ndupper, struct nameidata * ndparent)
{
	if (ndupper) {
		dput(ndupper->path.dentry);
		if (ndupper->path.mnt)
			mntput(ndupper->path.mnt);
	}
	if (ndparent) {
		dput(ndparent->path.dentry);
		if (ndparent->path.mnt)
			mntput(ndparent->path.mnt);
	}
}

int medusa_l1_inode_alloc_security(struct inode *inode);
/**
 * file_kobj_validate_dentry - get dentry security information from auth. server
 * @dentry: dentry to get the information for.
 * @mnt: optional vfsmount structure for that dentry
 *
 * This routine expects the existing, but !MED_MAGIC_VALID dentry.
 */
int file_kobj_validate_dentry(struct dentry * dentry, struct vfsmount * mnt)
{
	struct nameidata ndcurrent;
	struct nameidata ndupper;
	struct nameidata ndparent;

	INIT_MEDUSA_OBJECT_VARS(&inode_security(dentry->d_inode));
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
	cap_clear(inode_security(dentry->d_inode).pcap);
	inode_security(dentry->d_inode).icap = CAP_FULL_SET;
	inode_security(dentry->d_inode).ecap = CAP_FULL_SET;
#endif
	ndcurrent.path.dentry = dentry;
	ndcurrent.path.mnt = mnt; /* may be NULL */
	medusa_get_upper_and_parent(&ndcurrent, &ndupper, &ndparent);

	if (ndparent.path.dentry->d_inode == NULL) {
		medusa_put_upper_and_parent(&ndupper, &ndparent);
		return 0;
	}

	if (ndcurrent.path.dentry != ndparent.path.dentry) {
		if (&inode_security(ndcurrent.path.dentry->d_inode) == NULL) // dont know why? TODO find out
			medusa_l1_inode_alloc_security(ndcurrent.path.dentry->d_inode);

		if (&inode_security(ndparent.path.dentry->d_inode) == NULL) // dont know why? TODO find out
			medusa_l1_inode_alloc_security(ndparent.path.dentry->d_inode);

		if (!MED_MAGIC_VALID(&inode_security(ndparent.path.dentry->d_inode)) &&
			file_kobj_validate_dentry(ndparent.path.dentry, ndparent.path.mnt) <= 0) {
			medusa_put_upper_and_parent(&ndupper, &ndparent);
			return 0;
		}

		if (!MEDUSA_MONITORED_ACCESS_O(getfile_event,
					&inode_security(ndparent.path.dentry->d_inode))) {

			COPY_MEDUSA_OBJECT_VARS(&inode_security(ndcurrent.path.dentry->d_inode),
					&inode_security(ndparent.path.dentry->d_inode));
			inode_security(ndcurrent.path.dentry->d_inode).user = inode_security(ndparent.path.dentry->d_inode).user;
#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES                                                
			inode_security(ndcurrent.path.dentry->d_inode).icap = inode_security(ndparent.path.dentry->d_inode).icap;
			inode_security(ndcurrent.path.dentry->d_inode).pcap = inode_security(ndparent.path.dentry->d_inode).pcap;
			inode_security(ndcurrent.path.dentry->d_inode).ecap = inode_security(ndparent.path.dentry->d_inode).ecap;
#endif
			medusa_put_upper_and_parent(&ndupper, &ndparent);
			return 1;
		}
	}

	/* we're global root, or cannot inherit from our parent */

	if (do_file_kobj_validate_dentry(&ndcurrent, &ndupper, &ndparent)
			!= MED_ERR) {
		medusa_put_upper_and_parent(&ndupper, &ndparent);
		return MED_MAGIC_VALID(&inode_security(ndcurrent.path.dentry->d_inode));
	}
	medusa_put_upper_and_parent(&ndupper, &ndparent);
	return -1;
}

static medusa_answer_t do_file_kobj_validate_dentry(struct nameidata * ndcurrent,
		struct nameidata * ndupper, struct nameidata * ndparent)
{
	struct getfile_event event;
	struct file_kobject file;
	struct file_kobject directory;
	medusa_answer_t retval;

	file_kern2kobj(&file, ndcurrent->path.dentry->d_inode);
	file_kobj_dentry2string(ndupper->path.dentry, event.filename);
	file_kern2kobj(&directory, ndparent->path.dentry->d_inode);
	file_kobj_live_add(ndcurrent->path.dentry->d_inode);
	file_kobj_live_add(ndparent->path.dentry->d_inode);
	retval = MED_DECIDE(getfile_event, &event, &file, &directory);
	file_kobj_live_remove(ndparent->path.dentry->d_inode);
	file_kobj_live_remove(ndcurrent->path.dentry->d_inode);
	return retval;
}

int __init getfile_evtype_init(void) {
	MED_REGISTER_EVTYPE(getfile_event,
			MEDUSA_EVTYPE_TRIGGEREDATSUBJECT |
			MEDUSA_EVTYPE_TRIGGEREDBYOBJECTTBIT);
	return 0;
}
__initcall(getfile_evtype_init);
