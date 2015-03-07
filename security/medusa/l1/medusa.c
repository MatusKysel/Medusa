#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <asm/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/cred.h>
#include <linux/medusa/l3/registry.h>
#include <linux/medusa/l1/inode.h> 
#include <linux/medusa/l4/comm.h>
#include <linux/medusa/l1/file_handlers.h>
#include <linux/medusa/l1/task.h>
#include <linux/medusa/l1/process_handlers.h>
#include "../l2/kobject_process.h"
#include "../l2/kobject_file.h"

#define work (min > 10)

static int min = 0;

#define MEDUSA_CHECK(d) if (min++ < 40) { \
	printk("medusa: current %s - %p - %p - %s\n", __func__, current, &task_security(current), current->comm);  \
	if (d != NULL) \
		printk("medusa: denty: %s - %p - %p - %s\n", __func__, d, ((struct dentry*)d)->d_inode, ((struct dentry*)d)->d_name.name); \
	else  \
		min--; \
	}
#ifdef CONFIG_SECURITY_MEDUSA

static int medusa_l1_cred_alloc_blank(struct cred *cred, gfp_t gfp);
int medusa_l1_inode_alloc_security(struct inode *inode);


static int medusa_l1_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return 0;
}

static int medusa_l1_quota_on(struct dentry *dentry)
{
	return 0;
}

static int medusa_l1_bprm_check_security (struct linux_binprm *bprm)
{
	return 0;
}

static void medusa_l1_bprm_committing_creds(struct linux_binprm *bprm)
{
}

static void medusa_l1_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static int medusa_l1_sb_alloc_security(struct super_block *sb)
{
	return 0;
}

static void medusa_l1_sb_free_security(struct super_block *sb)
{
}

static int medusa_l1_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

static int medusa_l1_sb_remount(struct super_block *sb, void *data)
{
	return 0;
} 

static int medusa_l1_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
        struct dentry *root = sb->s_root;
        struct inode *inode = root->d_inode;

	if (&inode_security(inode) == NULL)
		medusa_l1_inode_alloc_security(inode);
	printk("medusa: sb_kern_mount\n");
	return 0;
}

static int medusa_l1_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return 0;
}

static int medusa_l1_sb_statfs(struct dentry *dentry)
{
	return 0;
}

static int medusa_l1_sb_mount(const char *dev_name, struct path *path, const char *type,
			unsigned long flags, void *data)
{
	return 0;
}

static int medusa_l1_sb_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}


static int medusa_l1_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	return 0;
}

static int medusa_l1_sb_set_mnt_opts(struct super_block *sb,
			       struct security_mnt_opts *opts,
                                unsigned long kern_flags,
                                unsigned long *set_kern_flags)
{
	if (unlikely(opts->num_mnt_opts))
		return -EOPNOTSUPP;
	return 0;
}

static int medusa_l1_sb_clone_mnt_opts(const struct super_block *oldsb,
				  struct super_block *newsb)
{
	return 0;
}

static int medusa_l1_sb_parse_opts_str(char *options, struct security_mnt_opts *opts)
{
	return 0;
}

static int medusa_l1_dentry_init_security(struct dentry *dentry, int mode, 
					struct qstr *name, void **ctx, u32 *ctxlen)
{
	if (dentry->d_inode != NULL) {
		if (&inode_security(dentry->d_inode) == NULL)
			medusa_l1_inode_alloc_security(dentry->d_inode);

	}
	return -EOPNOTSUPP;
}

int medusa_l1_inode_alloc_security(struct inode *inode)
{
        struct medusa_l1_inode_s *med;

	med = (struct medusa_l1_inode_s*) kmalloc(sizeof(struct medusa_l1_inode_s), GFP_KERNEL);

        if (med == NULL)
        	return -ENOMEM;

	inode->i_security = med;
	medusa_clean_inode(inode);

        return 0;
}

static void medusa_l1_inode_free_security(struct inode *inode)
{
        struct medusa_l1_inode_s *med;

	if (inode->i_security != NULL) {
		rcu_read_lock();
		med = inode->i_security;
		inode->i_security = NULL;
		rcu_read_unlock();
		kfree(med);
	}
}

static int medusa_l1_inode_init_security(struct inode *inode, struct inode *dir,
                                    const struct qstr *qstr, const char **name,
                                    void **value, size_t *len)
{
	medusa_clean_inode(inode);

	return 0;
}

static int medusa_l1_inode_create(struct inode *inode, struct dentry *dentry,
			    umode_t mode)
{
	MEDUSA_CHECK(dentry)
	return 0;
	if (!work)
		return 0;
	if (medusa_create(dentry, mode) == MED_NO)
		return -EACCES;

	return 0;
}

static int medusa_l1_inode_link(struct dentry *old_dentry, struct inode *inode,
			  struct dentry *new_dentry)
{
	MEDUSA_CHECK(old_dentry)

	if (!work) {
		return 0;
	}
	
	if (medusa_link(old_dentry, new_dentry->d_name.name) == MED_NO)
		return -EPERM;

	return 0;
}

static int medusa_l1_inode_unlink(struct inode *inode, struct dentry *dentry)
{
	MEDUSA_CHECK(dentry)
	return 0;

	if (!work) {
		return 0;
	}
	if (medusa_unlink(dentry) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_symlink(struct inode *inode, struct dentry *dentry,
			     const char *name)
{
	MEDUSA_CHECK(dentry)
	return 0;
	if (!work) {
		return 0;
	}
	
	if (medusa_symlink(dentry, name) == MED_NO)
		return -EPERM;
	
	return 0;
}

static int medusa_l1_inode_mkdir(struct inode *inode, struct dentry *dentry,
			   	umode_t mask)
{
	MEDUSA_CHECK(dentry)
	return 0;
	if (!work)
		return 0;
	if(medusa_mkdir(dentry, mask) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_rmdir(struct inode *inode, struct dentry *dentry)
{
	MEDUSA_CHECK(dentry)
	return 0;
	if (!work)
		return 0;
	if (medusa_rmdir(dentry) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_mknod(struct inode *inode, struct dentry *dentry,
			   umode_t mode, dev_t dev)
{
	MEDUSA_CHECK(dentry)
	return 0;
	if (!work)
		return 0;
	if(medusa_mknod(dentry, dev, mode) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	MEDUSA_CHECK(old_dentry)
	MEDUSA_CHECK(new_dentry)
	return 0;
	if (!work)
		return 0;
	if (medusa_rename(old_dentry, new_dentry->d_name.name) == MED_NO)
		return -EPERM;
	return 0;
}

static int medusa_l1_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static int medusa_l1_inode_follow_link(struct dentry *dentry,
				 struct nameidata *nameidata)
{
	return 0;
}

static int medusa_l1_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

static int medusa_l1_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int medusa_l1_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}

static void medusa_l1_inode_post_setxattr(struct dentry *dentry, const char *name,
				    const void *value, size_t size, int flags)
{
}

static int medusa_l1_inode_getxattr(struct dentry *dentry, const char *name)
{
	return 0;
}

static int medusa_l1_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static int medusa_l1_inode_getsecurity(const struct inode *inode, const char *name,
				 void **buffer, bool alloc)
{
	return -EOPNOTSUPP;
	return 0;
}

static int medusa_l1_inode_setsecurity(struct inode *inode, const char *name,
				 const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
	return 0;
}

static int medusa_l1_inode_listsecurity(struct inode *inode, char *buffer,
				  size_t buffer_size)
{
	return 0;
}

static void medusa_l1_inode_getsecid(const struct inode *inode, u32 *secid)
{
	*secid = 0;
}

#ifdef CONFIG_SECURITY_PATH
static int medusa_l1_path_mknod(struct path *dir, struct dentry *dentry, umode_t mode,
			  	unsigned int dev)
{
	return 0;
}

static int medusa_l1_path_mkdir(struct path *dir, struct dentry *dentry, umode_t mode)
{
	return 0;
}

static int medusa_l1_path_rmdir(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static int medusa_l1_path_unlink(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static int medusa_l1_path_symlink(struct path *dir, struct dentry *dentry,
			    const char *old_name)
{
	return 0;
}

static int medusa_l1_path_link(struct dentry *old_dentry, struct path *new_dir,
			 struct dentry *new_dentry)
{
	return 0;
}

static int medusa_l1_path_rename(struct path *old_path, struct dentry *old_dentry,
			   struct path *new_path, struct dentry *new_dentry)
{
	return 0;
}

static int medusa_l1_path_truncate(struct path *path)
{
	return 0;
}

static int medusa_l1_path_chmod(struct path *path,
			  umode_t mode)
{
	return 0;
}

static int medusa_l1_path_chown(struct path *path, kuid_t uid, kgid_t gid)
{
	return 0;
}

static int medusa_l1_path_chroot(struct path *root)
{
	return 0;
}
#endif

static int medusa_l1_file_permission(struct file *file, int mask)
{
	//printk("medusa: file_permission called\n");
	return 0;
}

static int medusa_l1_file_alloc_security(struct file *file)
{
	return 0;
}

static void medusa_l1_file_free_security(struct file *file)
{
}

static int medusa_l1_file_ioctl(struct file *file, unsigned int command,
			  unsigned long arg)
{
	return 0;
}

static int medusa_l1_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			     unsigned long prot)
{
	return 0;
}

static int medusa_l1_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static int medusa_l1_file_fcntl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	return 0;
}

static void medusa_l1_file_set_fowner(struct file *file)
{
	return;
}

static int medusa_l1_file_send_sigiotask(struct task_struct *tsk,
				   struct fown_struct *fown, int sig)
{
	return 0;
}

static int medusa_l1_file_receive(struct file *file)
{
	return 0;
}

//static int medusa_l1_dentry_open(struct file *file, const struct cred *cred)
//{
//	return 0;
//}

static int medusa_l1_task_create(unsigned long clone_flags)
{
	return 0;
}

static void medusa_l1_task_free(struct task_struct *task)
{
}

static int medusa_l1_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct medusa_l1_task_s* med;
	struct cred* tmp;

	printk("medusa: init security: %s task\n", current->comm);
	
	med = (struct medusa_l1_task_s*) kmalloc(sizeof(struct medusa_l1_task_s), gfp);
	
	if (med == NULL)
	        return -ENOMEM;
	
	cred->security = med;

	tmp = (struct cred*) current->cred;
	current->cred = cred;

	medusa_init_process(current);
	current->cred = tmp;
	
	return 0;
}

static void medusa_l1_cred_free(struct cred *cred)
{
	if (cred->security)
		kfree(cred->security);

	cred->security = NULL;
}

static int medusa_l1_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	struct medusa_l1_task_s* med;
	
	if (old->security == NULL || new->security != NULL) {
		return 0;
	}
		
	med = (struct medusa_l1_task_s*) kmalloc(sizeof(struct medusa_l1_task_s), gfp);

	if (med == NULL) {
	        return -ENOMEM;
	}

	memcpy(med, old->security, sizeof(struct medusa_l1_task_s));

	new->security = med;
	
	return 0;
}

static void medusa_l1_cred_transfer(struct cred *new, const struct cred *old)
{
	//medusa_l1_cred_prepare(new, old, GFP_KERNEL);
	//medusa_l1_cred_alloc_blank(new, GFP_KERNEL);
	return;
}

static int medusa_l1_kernel_act_as(struct cred *new, u32 secid)
{
	return 0;
}

static int medusa_l1_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	return 0;
}

static int medusa_l1_kernel_module_request(char *kmod_name)
{
	return 0;
}

static int medusa_l1_kernel_module_from_file(struct file *file)
{
	return 0;
}

static int medusa_l1_task_fix_setuid(struct cred *new, const struct cred *old,
                                int flags)
{
	return cap_task_fix_setuid(new, old, flags);
}

static int medusa_l1_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int medusa_l1_task_getpgid(struct task_struct *p)
{
	return 0;
}

static int medusa_l1_task_getsid(struct task_struct *p)
{
	return 0;
}

static void medusa_l1_task_getsecid(struct task_struct *p, u32 *secid)
{
	*secid = 0;
}

static int medusa_l1_task_getioprio(struct task_struct *p)
{
	return 0;
}

static int medusa_l1_task_setrlimit(struct task_struct *p, unsigned int resource,
				 struct rlimit *new_rlim)
{
	return 0;
}

static int medusa_l1_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static int medusa_l1_task_movememory(struct task_struct *p)
{
	return 0;
}

static int medusa_l1_task_wait(struct task_struct *p)
{
	return 0;
}

static int medusa_l1_task_kill(struct task_struct *p, struct siginfo *info,
			 int sig, u32 secid)
{
	return 0;
}

static void medusa_l1_task_to_inode(struct task_struct *p, struct inode *inode)
{
}

static int medusa_l1_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	return 0;
}

static void medusa_l1_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
	*secid = 0;
}

static int medusa_l1_msg_msg_alloc_security(struct msg_msg *msg)
{
	return 0;
}

static void medusa_l1_msg_msg_free_security(struct msg_msg *msg)
{
}

static int medusa_l1_msg_queue_alloc_security(struct msg_queue *msq)
{
	return 0;
}

static void medusa_l1_msg_queue_free_security(struct msg_queue *msq)
{
}

static int medusa_l1_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
	return 0;
}

static int medusa_l1_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
	return 0;
}

static int medusa_l1_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg,
				int msgflg)
{
	return 0;
}

static int medusa_l1_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
				struct task_struct *target, long type, int mode)
{
	return 0;
}

static int medusa_l1_shm_alloc_security(struct shmid_kernel *shp)
{
	return 0;
}

static void medusa_l1_shm_free_security(struct shmid_kernel *shp)
{
}

static int medusa_l1_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	return 0;
}

static int medusa_l1_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return 0;
}

static int medusa_l1_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,
			 int shmflg)
{
	return 0;
}

static int medusa_l1_sem_alloc_security(struct sem_array *sma)
{
	return 0;
}

static void medusa_l1_sem_free_security(struct sem_array *sma)
{
}

static int medusa_l1_sem_associate(struct sem_array *sma, int semflg)
{
	return 0;
}

static int medusa_l1_sem_semctl(struct sem_array *sma, int cmd)
{
	return 0;
}

static int medusa_l1_sem_semop(struct sem_array *sma, struct sembuf *sops,
			 unsigned nsops, int alter)
{
	return 0;
}

#ifdef CONFIG_SECURITY_NETWORK
static int medusa_l1_unix_stream_connect(struct sock *sock, struct sock *other,
				   struct sock *newsk)
{
	//printk("medusa: unix_stream_connect called\n");
	return 0;
}

static int medusa_l1_unix_may_send(struct socket *sock, struct socket *other)
{
	return 0;
}

static int medusa_l1_socket_create(int family, int type, int protocol, int kern)
{
	//printk("medusa: socket_create called\n"); 
	return 0;
}

static int medusa_l1_socket_post_create(struct socket *sock, int family, int type,
				  int protocol, int kern)
{
	return 0;
}

static int medusa_l1_socket_bind(struct socket *sock, struct sockaddr *address,
			   int addrlen)
{
	return 0;
}

static int medusa_l1_socket_connect(struct socket *sock, struct sockaddr *address,
			      int addrlen)
{
	//printk("medusa: socket_connect called\n");
	return 0;
}

static int medusa_l1_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}

static int medusa_l1_socket_accept(struct socket *sock, struct socket *newsock)
{
	return 0;
}

static int medusa_l1_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	return 0;
}

static int medusa_l1_socket_recvmsg(struct socket *sock, struct msghdr *msg,
			      int size, int flags)
{
	return 0;
}

static int medusa_l1_socket_getsockname(struct socket *sock)
{
	return 0;
}

static int medusa_l1_socket_getpeername(struct socket *sock)
{
	return 0;
}

static int medusa_l1_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int medusa_l1_socket_getsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int medusa_l1_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}

static int medusa_l1_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int medusa_l1_socket_getpeersec_stream(struct socket *sock,
					char __user *optval,
					int __user *optlen, unsigned len)
{
	return 0;
}

static int medusa_l1_socket_getpeersec_dgram(struct socket *sock,
				       struct sk_buff *skb, u32 *secid)
{
	return 0;
}

static int medusa_l1_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

static void medusa_l1_sk_free_security(struct sock *sk)
{
}

static void medusa_l1_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
}

static void medusa_l1_sk_getsecid(struct sock *sk, u32 *secid)
{
}

static void medusa_l1_sock_graft(struct sock *sk, struct socket *parent)
{
}

static int medusa_l1_inet_conn_request(struct sock *sk, struct sk_buff *skb,
				 struct request_sock *req)
{
	return 0;
}

static void medusa_l1_inet_csk_clone(struct sock *newsk,
			       const struct request_sock *req)
{
}

static void medusa_l1_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
}

static int medusa_l1_secmark_relabel_packet(u32 secid)
{
        return 0;
}


static void medusa_l1_secmark_refcount_inc(void)
{
}


static void medusa_l1_secmark_refcount_dec(void)
{
}


static void medusa_l1_req_classify_flow(const struct request_sock *req,
				  struct flowi *fl)
{
}

static int medusa_l1_tun_dev_alloc_security(void **security)
{
	return 0;
}

static void medusa_l1_tun_dev_free_security(void *security)
{
}

static int medusa_l1_tun_dev_create(void)
{
	return 0;
}

//static void medusa_l1_tun_dev_post_create(struct sock *sk)
//{
//}

static int medusa_l1_tun_dev_attach_queue(void *security)
{
	return 0;
}

static int medusa_l1_tun_dev_attach(struct sock *sk, void* security)
{
	return 0;
}

static int medusa_l1_tun_dev_open(void *security)
{
	return 0;
}

static void medusa_l1_skb_owned_by(struct sk_buff *skb, struct sock *sk)
{
}

#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
static int medusa_l1_xfrm_policy_alloc(struct xfrm_sec_ctx **ctxp,
                                          struct xfrm_user_sec_ctx *sec_ctx,
                                          gfp_t gfp)

{
	return 0;
}

static int medusa_l1_xfrm_policy_clone(struct xfrm_sec_ctx *old_ctx,
					  struct xfrm_sec_ctx **new_ctxp)
{
	return 0;
}

static void medusa_l1_xfrm_policy_free(struct xfrm_sec_ctx *ctx)
{
}

static int medusa_l1_xfrm_policy_delete(struct xfrm_sec_ctx *ctx)
{
	return 0;
}

static int medusa_l1_xfrm_state_alloc(struct xfrm_state *x,
					 struct xfrm_user_sec_ctx *sec_ctx)
{
	return 0;
}

static int medusa_l1_xfrm_state_alloc_acquire(struct xfrm_state *x,
					 struct xfrm_sec_ctx *polsec,
					 u32 secid)
{
	return 0;
}

static void medusa_l1_xfrm_state_free(struct xfrm_state *x)
{
}

static int medusa_l1_xfrm_state_delete(struct xfrm_state *x)
{
	return 0;
}

static int medusa_l1_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 sk_sid, u8 dir)
{
	return 0;
}

static int medusa_l1_xfrm_state_pol_flow_match(struct xfrm_state *x,
					 struct xfrm_policy *xp,
					 const struct flowi *fl)
{
	return 1;
}

static int medusa_l1_xfrm_decode_session(struct sk_buff *skb, u32 *fl, int ckall)
{
	return 0;
}

#endif /* CONFIG_SECURITY_NETWORK_XFRM */
static void medusa_l1_d_instantiate(struct dentry *dentry, struct inode *inode)
{
}

static int medusa_l1_getprocattr(struct task_struct *p, char *name, char **value)
{
	return -EINVAL;
}

static int medusa_l1_setprocattr(struct task_struct *p, char *name, void *value,
			   size_t size)
{
	return -EINVAL;
}

static int medusa_l1_ismaclabel(const char *name) 
{
	return 0;
}

static int medusa_l1_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return -EOPNOTSUPP;
}

static int medusa_l1_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return -EOPNOTSUPP;
}

static void medusa_l1_release_secctx(char *secdata, u32 seclen)
{
}

static int medusa_l1_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen)
{
	return -EOPNOTSUPP;
}

static int medusa_l1_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen)
{
	return -EOPNOTSUPP;
}

static int medusa_l1_inode_getsecctx(struct inode *inode, void **ctx, u32 *ctxlen)
{
	return -EOPNOTSUPP;
}
#ifdef CONFIG_KEYS
static int medusa_l1_key_alloc(struct key *key, const struct cred *cred,
			 unsigned long flags)
{
	return 0;
}

static void medusa_l1_key_free(struct key *key)
{
}

static int medusa_l1_key_permission(key_ref_t key_ref, const struct cred *cred,
			      key_perm_t perm)
{
	return 0;
}

static int medusa_l1_key_getsecurity(struct key *key, char **_buffer)
{
	*_buffer = NULL;
	return 0;
}

#endif /* CONFIG_KEYS */

#ifdef CONFIG_AUDIT
static int medusa_l1_audit_rule_init(u32 field, u32 op, char *rulestr, void **lsmrule)
{
	return 0;
}

static int medusa_l1_audit_rule_known(struct audit_krule *krule)
{
	return 0;
}

static int medusa_l1_audit_rule_match(u32 secid, u32 field, u32 op, void *lsmrule,
				struct audit_context *actx)
{
	return 0;
}

static void medusa_l1_audit_rule_free(void *lsmrule)
{
}
#endif /* CONFIG_AUDIT */


static int medusa_l1_ptrace_access_check(struct task_struct *child,
				     unsigned int mode)
{
	return 0;
}

static int medusa_l1_ptrace_traceme(struct task_struct *parent)
{
	return 0;
}

static int medusa_l1_capget(struct task_struct *target, kernel_cap_t *effective,
			  kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return 0;
}

static int medusa_l1_capset(struct cred *new, const struct cred *old,
			  const kernel_cap_t *effective,
			  const kernel_cap_t *inheritable,
			  const kernel_cap_t *permitted)
{
	return 0;	
}


static int medusa_l1_capable(const struct cred *cred,
			  struct user_namespace *ns, int cap, int audit)
{
	return 0;
}

static int medusa_l1_syslog(int type)
{
	return 0;
}

static int medusa_l1_settime(const struct timespec *ts, const struct timezone *tz)
{
	return 0;
}

static int medusa_l1_vm_enough_memory(struct mm_struct *mm, long pages)
{
	return 0;
}

static int medusa_l1_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	return cap_netlink_send(sk, skb);
}

//static int medusa_l1_netlink_recv(struct sk_buff *skb, int capability)
//{
//	return 0;	
//}

static int medusa_l1_bprm_set_creds(struct linux_binprm *bprm)
{
	return 0;
//	struct inode* inode = file_inode(bprm->file);
//	if (!work)
//		return 0;
//#ifdef CONFIG_MEDUSA_FILE_CAPABILITIES
//	if (MED_MAGIC_VALID(&inode_security(inode)) ||
//			file_kobj_validate_dentry(bprm->file->f_dentry,NULL) > 0) {
//		/* If the security daemon sets the file capabilities, use them */
//		bprm->cred->cap_inheritable = inode_security(inode).icap;
//		bprm->cred->cap_permitted = inode_security(inode).pcap;
//		bprm->cred->cap_effective = inode_security(inode).ecap;
//	}
//#endif /* CONFIG_MEDUSA_FILE_CAPABILITIES */
//
//	{
//		int retval;
//#ifndef CONFIG_MEDUSA_FILE_CAPABILITIES
//		kernel_cap_t new_permitted, working;
//
///* Privilege elevation check copied from compute_creds() */
//		new_permitted = cap_intersect(bprm->cap_permitted, cap_bset);
//		working = cap_intersect(bprm->cap_inheritable,
//					current->cap_inheritable);
//		new_permitted = cap_combine(new_permitted, working);
//#endif
//		if (!uid_eq(bprm->cred->euid,task_uid(current)) || !gid_eq(bprm->cred->egid, task_gid(current))
//#ifndef CONFIG_MEDUSA_FILE_CAPABILITIES
//		    || !cap_issubset(new_permitted, current->cap_permitted)
//#endif
//		   ) {
//			if ((retval = medusa_sexec(bprm)) == MED_NO)
//				return -EPERM;
//			if (retval == MED_SKIP) {
//				bprm->cred->euid = task_euid(current);
//				bprm->cred->egid = task_egid(current);
//#ifndef CONFIG_MEDUSA_FILE_CAPABILITIES
//				cap_clear(bprm->cap_inheritable);
//				bprm->cap_permitted = current->cap_permitted;
//				bprm->cap_effective = current->cap_effective;
//#endif
//			}
//		}
//	}
//	return 0;
}

static int medusa_l1_bprm_secureexec(struct linux_binprm *bprm)
{
	if (!work)
		return 0;

	return 0;

	if (medusa_sexec(bprm) == MED_NO)
		return -EPERM;

	return 0;
}
	

static int medusa_l1_inode_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
	return cap_inode_setxattr(dentry, name, value, size, flags);
} 


static int medusa_l1_inode_removexattr(struct dentry *dentry, const char *name)
{
	return cap_inode_removexattr(dentry, name);
} 

static int medusa_l1_inode_need_killpriv(struct dentry *dentry) 
{
	return cap_inode_need_killpriv(dentry);
}

static int medusa_l1_inode_killpriv(struct dentry *dentry)
{
	return cap_inode_killpriv(dentry);
}

static int medusa_l1_mmap_addr(unsigned long addr) 
{
	return cap_mmap_addr(addr);
}

static int medusa_l1_mmap_file(struct file *file,
                          unsigned long reqprot, unsigned long prot,
                          unsigned long flags)
{
	//printk("medusa: file_mmap called\n");
	return 0;
} 


static int medusa_l1_task_setnice(struct task_struct *p, int nice)
{
	return cap_task_setnice(p, nice);
} 


static int medusa_l1_task_setioprio(struct task_struct *p, int ioprio)
{
	return cap_task_setioprio(p, ioprio);
} 



static int medusa_l1_task_setscheduler(struct task_struct *p)
{
	return cap_task_setscheduler(p);
} 


static int medusa_l1_task_prctl(int option, unsigned long arg2,
                           unsigned long arg3, unsigned long arg4,
                           unsigned long arg5)
{
	return cap_task_prctl(option, arg2, arg3, arg4, arg5);
}


static struct security_operations medusa_l1_ops = {
	.name =				"medusa",

	.ptrace_access_check =		medusa_l1_ptrace_access_check,
	.ptrace_traceme =		medusa_l1_ptrace_traceme,
	.capget =			medusa_l1_capget,
	.capset =			medusa_l1_capset,
	.capable = 			medusa_l1_capable,
	.quotactl =			medusa_l1_quotactl,
	.quota_on =			medusa_l1_quota_on,
	.syslog =			medusa_l1_syslog,
	.settime = 			medusa_l1_settime,
	.vm_enough_memory =		medusa_l1_vm_enough_memory,

	.bprm_set_creds =		medusa_l1_bprm_set_creds,
	.bprm_check_security =		medusa_l1_bprm_check_security,
	.bprm_secureexec =		medusa_l1_bprm_secureexec,
	.bprm_committing_creds =	medusa_l1_bprm_committing_creds,
	.bprm_committed_creds =		medusa_l1_bprm_committed_creds,

	.sb_alloc_security =		medusa_l1_sb_alloc_security,
	.sb_free_security =		medusa_l1_sb_free_security,
	.sb_copy_data =			medusa_l1_sb_copy_data,
	.sb_remount =			medusa_l1_sb_remount,
	.sb_kern_mount =		medusa_l1_sb_kern_mount,
	.sb_show_options =		medusa_l1_sb_show_options,
	.sb_statfs =			medusa_l1_sb_statfs,
	.sb_mount =			medusa_l1_sb_mount,
	.sb_umount =			medusa_l1_sb_umount,
	.sb_pivotroot = 		medusa_l1_sb_pivotroot,
	.sb_set_mnt_opts =		medusa_l1_sb_set_mnt_opts,
	.sb_clone_mnt_opts =		medusa_l1_sb_clone_mnt_opts,
	.sb_parse_opts_str = 		medusa_l1_sb_parse_opts_str,
	.dentry_init_security =		medusa_l1_dentry_init_security,

#ifdef CONFIG_SECURITY_PATH
        .path_unlink = 			medusa_l1_path_unlink,
        .path_mkdir = 			medusa_l1_path_mkdir,
        .path_rmdir =			medusa_l1_path_rmdir,
        .path_mknod =			medusa_l1_path_mknod,
        .path_truncate =		medusa_l1_path_truncate,
        .path_symlink =			medusa_l1_path_symlink,
        .path_link =			medusa_l1_path_link,
        .path_rename =			medusa_l1_path_rename,
        .path_chmod =			medusa_l1_path_chmod,
        .path_chown =			medusa_l1_path_chown,
        .path_chroot =			medusa_l1_path_chroot,
#endif

	.inode_alloc_security =		medusa_l1_inode_alloc_security,
	.inode_free_security =		medusa_l1_inode_free_security,
	.inode_init_security =		medusa_l1_inode_init_security,
	.inode_create =			medusa_l1_inode_create,
	.inode_link =			medusa_l1_inode_link,
	.inode_unlink =			medusa_l1_inode_unlink,
	.inode_symlink =		medusa_l1_inode_symlink,
	.inode_mkdir =			medusa_l1_inode_mkdir,
	.inode_rmdir =			medusa_l1_inode_rmdir,
	.inode_mknod =			medusa_l1_inode_mknod,
	.inode_rename =			medusa_l1_inode_rename,
	.inode_readlink =		medusa_l1_inode_readlink,
	.inode_follow_link =		medusa_l1_inode_follow_link,
	.inode_permission =		medusa_l1_inode_permission,
	.inode_setattr =		medusa_l1_inode_setattr,
	.inode_getattr =		medusa_l1_inode_getattr,
	.inode_setxattr =		medusa_l1_inode_setxattr,
	.inode_post_setxattr =		medusa_l1_inode_post_setxattr,
	.inode_getxattr =		medusa_l1_inode_getxattr,
	.inode_listxattr =		medusa_l1_inode_listxattr,
	.inode_removexattr =		medusa_l1_inode_removexattr,
	.inode_need_killpriv = 		medusa_l1_inode_need_killpriv,
	.inode_killpriv	=		medusa_l1_inode_killpriv,
	.inode_getsecurity =		medusa_l1_inode_getsecurity,
	.inode_setsecurity =		medusa_l1_inode_setsecurity,
	.inode_listsecurity =		medusa_l1_inode_listsecurity,
	.inode_getsecid =		medusa_l1_inode_getsecid,

	.file_permission =		medusa_l1_file_permission,
	.file_alloc_security =		medusa_l1_file_alloc_security,
	.file_free_security =		medusa_l1_file_free_security,
	.file_ioctl =			medusa_l1_file_ioctl,
	.mmap_addr =			medusa_l1_mmap_addr,
	.mmap_file =			medusa_l1_mmap_file,
	.file_mprotect =		medusa_l1_file_mprotect,
	.file_lock =			medusa_l1_file_lock,
	.file_fcntl =			medusa_l1_file_fcntl,
	.file_set_fowner =		medusa_l1_file_set_fowner,
	.file_send_sigiotask =		medusa_l1_file_send_sigiotask,
	.file_receive =			medusa_l1_file_receive,

	//.dentry_open =			medusa_l1_dentry_open,

	.task_create =			medusa_l1_task_create,
	.task_free = 			medusa_l1_task_free,
	.cred_alloc_blank =		medusa_l1_cred_alloc_blank,
	.cred_free =			medusa_l1_cred_free,
	.cred_prepare =			medusa_l1_cred_prepare,
	.cred_transfer =		medusa_l1_cred_transfer,
	.kernel_act_as =		medusa_l1_kernel_act_as,
	.kernel_create_files_as =	medusa_l1_kernel_create_files_as,
	.kernel_module_request =	medusa_l1_kernel_module_request,
	.kernel_module_from_file = 	medusa_l1_kernel_module_from_file,
	.task_fix_setuid = 		medusa_l1_task_fix_setuid,
	.task_setpgid =			medusa_l1_task_setpgid,
	.task_getpgid =			medusa_l1_task_getpgid,
	.task_getsid =			medusa_l1_task_getsid,
	.task_getsecid =		medusa_l1_task_getsecid,
	.task_setnice =			medusa_l1_task_setnice,
	.task_setioprio =		medusa_l1_task_setioprio,
	.task_getioprio =		medusa_l1_task_getioprio,
	.task_setrlimit =		medusa_l1_task_setrlimit,
	.task_setscheduler =		medusa_l1_task_setscheduler,
	.task_getscheduler =		medusa_l1_task_getscheduler,
	.task_movememory =		medusa_l1_task_movememory,
	.task_kill =			medusa_l1_task_kill,
	.task_wait =			medusa_l1_task_wait,
	.task_prctl =			medusa_l1_task_prctl,
	.task_to_inode =		medusa_l1_task_to_inode,

	.ipc_permission =		medusa_l1_ipc_permission,
	.ipc_getsecid =			medusa_l1_ipc_getsecid,

	.msg_msg_alloc_security =	medusa_l1_msg_msg_alloc_security,
	.msg_msg_free_security =	medusa_l1_msg_msg_free_security,

	.msg_queue_alloc_security =	medusa_l1_msg_queue_alloc_security,
	.msg_queue_free_security =	medusa_l1_msg_queue_free_security,
	.msg_queue_associate =		medusa_l1_msg_queue_associate,
	.msg_queue_msgctl =		medusa_l1_msg_queue_msgctl,
	.msg_queue_msgsnd =		medusa_l1_msg_queue_msgsnd,
	.msg_queue_msgrcv =		medusa_l1_msg_queue_msgrcv,

	.shm_alloc_security =		medusa_l1_shm_alloc_security,
	.shm_free_security =		medusa_l1_shm_free_security,
	.shm_associate =		medusa_l1_shm_associate,
	.shm_shmctl =			medusa_l1_shm_shmctl,
	.shm_shmat =			medusa_l1_shm_shmat,

	.sem_alloc_security =		medusa_l1_sem_alloc_security,
	.sem_free_security =		medusa_l1_sem_free_security,
	.sem_associate =		medusa_l1_sem_associate,
	.sem_semctl =			medusa_l1_sem_semctl,
	.sem_semop =			medusa_l1_sem_semop,

	.netlink_send =			medusa_l1_netlink_send,
	//.netlink_recv = 		medusa_l1_netlink_recv,

	.d_instantiate =		medusa_l1_d_instantiate,

	.getprocattr =			medusa_l1_getprocattr,
	.setprocattr =			medusa_l1_setprocattr,

	.ismaclabel =			medusa_l1_ismaclabel,

	.secid_to_secctx =		medusa_l1_secid_to_secctx,
	.secctx_to_secid =		medusa_l1_secctx_to_secid,
	.release_secctx =		medusa_l1_release_secctx,

	.inode_notifysecctx =		medusa_l1_inode_notifysecctx,
	.inode_setsecctx =		medusa_l1_inode_setsecctx,
	.inode_getsecctx =		medusa_l1_inode_getsecctx,

#ifdef CONFIG_SECURITY_NETWORK
	.unix_stream_connect =		medusa_l1_unix_stream_connect,
	.unix_may_send =		medusa_l1_unix_may_send,

	.socket_create =		medusa_l1_socket_create,
	.socket_post_create =		medusa_l1_socket_post_create,
	.socket_bind =			medusa_l1_socket_bind,
	.socket_connect =		medusa_l1_socket_connect,
	.socket_listen =		medusa_l1_socket_listen,
	.socket_accept =		medusa_l1_socket_accept,
	.socket_sendmsg =		medusa_l1_socket_sendmsg,
	.socket_recvmsg =		medusa_l1_socket_recvmsg,
	.socket_getsockname =		medusa_l1_socket_getsockname,
	.socket_getpeername =		medusa_l1_socket_getpeername,
	.socket_getsockopt =		medusa_l1_socket_getsockopt,
	.socket_setsockopt =		medusa_l1_socket_setsockopt,
	.socket_shutdown =		medusa_l1_socket_shutdown,
	.socket_sock_rcv_skb =		medusa_l1_socket_sock_rcv_skb,
	.socket_getpeersec_stream =	medusa_l1_socket_getpeersec_stream,
	.socket_getpeersec_dgram =	medusa_l1_socket_getpeersec_dgram,
	.sk_alloc_security =		medusa_l1_sk_alloc_security,
	.sk_free_security =		medusa_l1_sk_free_security,
	.sk_clone_security =		medusa_l1_sk_clone_security,
	.sk_getsecid =			medusa_l1_sk_getsecid,
	.sock_graft =			medusa_l1_sock_graft,
	.inet_conn_request =		medusa_l1_inet_conn_request,
	.inet_csk_clone =		medusa_l1_inet_csk_clone,
	.inet_conn_established =	medusa_l1_inet_conn_established,
	.secmark_relabel_packet =	medusa_l1_secmark_relabel_packet,
        .secmark_refcount_inc =		medusa_l1_secmark_refcount_inc,
        .secmark_refcount_dec =		medusa_l1_secmark_refcount_dec,
	.req_classify_flow =		medusa_l1_req_classify_flow,
	.tun_dev_alloc_security =	medusa_l1_tun_dev_alloc_security,
	.tun_dev_free_security =	medusa_l1_tun_dev_free_security,
	.tun_dev_create =		medusa_l1_tun_dev_create,
	.tun_dev_attach_queue =		medusa_l1_tun_dev_attach_queue,
	//.tun_dev_post_create = 		medusa_l1_tun_dev_post_create,
	.tun_dev_attach =		medusa_l1_tun_dev_attach,
	.tun_dev_open =			medusa_l1_tun_dev_open,
	.skb_owned_by =			medusa_l1_skb_owned_by,
#endif  /* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
	.xfrm_policy_alloc_security =	medusa_l1_xfrm_policy_alloc,
	.xfrm_policy_clone_security =	medusa_l1_xfrm_policy_clone,
	.xfrm_policy_free_security =	medusa_l1_xfrm_policy_free,
	.xfrm_policy_delete_security =	medusa_l1_xfrm_policy_delete,
	.xfrm_state_alloc =		medusa_l1_xfrm_state_alloc,
	.xfrm_state_alloc_acquire =	medusa_l1_xfrm_state_alloc_acquire,
	.xfrm_state_free_security =	medusa_l1_xfrm_state_free,
	.xfrm_state_delete_security =	medusa_l1_xfrm_state_delete,
	.xfrm_policy_lookup =		medusa_l1_xfrm_policy_lookup,
	.xfrm_state_pol_flow_match =	medusa_l1_xfrm_state_pol_flow_match,
	.xfrm_decode_session =		medusa_l1_xfrm_decode_session,
#endif

#ifdef CONFIG_KEYS
	.key_alloc =			medusa_l1_key_alloc,
	.key_free =			medusa_l1_key_free,
	.key_permission =		medusa_l1_key_permission,
	.key_getsecurity =		medusa_l1_key_getsecurity,
#endif

#ifdef CONFIG_AUDIT
	.audit_rule_init =		medusa_l1_audit_rule_init,
	.audit_rule_known =		medusa_l1_audit_rule_known,
	.audit_rule_match =		medusa_l1_audit_rule_match,
	.audit_rule_free =		medusa_l1_audit_rule_free,
#endif
};

void __init medusa_init(void);

static int __init medusa_l1_init(void){
	struct task_struct* process;
	//struct inode* inode; unused JK march 2015

	/* register the hooks */	
	if (!security_module_enable(&medusa_l1_ops)) {
		return 0;
	}

	if (register_security(&medusa_l1_ops))
		panic("medusa: Unable to register medusa with kernel.\n");
	else 
		printk("medusa: registered with the kernel\n");


	medusa_init();

	for_each_process(process) {
        	struct medusa_l1_task_s* med;
        	struct cred* tmp;
		MEDUSA_CHECK(NULL);

		if (&task_security(process) != NULL) {
			continue;
		}

        	med = (struct medusa_l1_task_s*) kmalloc(sizeof(struct medusa_l1_task_s), GFP_KERNEL);

        	if (med == NULL)
        	        return -ENOMEM;

        	tmp = (struct cred*) process->cred;
		tmp->security = med;

        	medusa_init_process(process);
		MEDUSA_CHECK(NULL);
	}
	min = -10;

	return 0;
}

static void __exit medusa_l1_exit (void)
{	
	printk("medusa unload");
	return;
}



module_init (medusa_l1_init);
module_exit (medusa_l1_exit);
MODULE_LICENSE("GPL");
#endif /* CONFIG_SECURITY_MEDUSA */

