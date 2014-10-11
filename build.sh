#!/bin/bash 

if [[ "$1" == '-h' || "$1" == '--help' ]]; then
	echo "$0 [--help] [--delete] [--clean]";
	exit 0
fi

if [ ! -f .dest ]; then
	echo -n "Prosim zadaj adresu kam sa maju kopirovat zdrojaky (NONE pre nikam): "
	read DEST
	echo $DEST > .dest
fi
DEST=`cat .dest`

minor=0
major=0
[ -f .minor ] && minor=`cat .minor`
[ -f .major ] && major=`cat .major`
echo $(($minor + 1)) > .minor
if [[ "$1" == '--delete' || "$1" == '-delete' ]]; then
	sudo find security/ -name '*.o' -delete
	sudo find security/ -name '*.cmd' -delete
elif [[ "$1" == '--clean' || "$1" == '-clean' ]]; then
	sudo make clean
fi
sudo rm vmlinux 2> /dev/null

#make -j4

#[ $? -ne 0 ] && exit 1


sudo rm -rf ../linux-image-*.deb

export CONCURRENCY_LEVEL=4
#export CLEAN_SOURCE=no
sudo make-kpkg --initrd --revision=1.2 --append_to_version medusa kernel_image

[ $? -ne 0 ] && exit 1

PID=0
if [ "$DEST" != "NONE" ]; then
	rsync -avz --exclude 'Documentation' --exclude '*.o' --exclude '.*' --exclude '*.cmd' --exclude '.git' --exclude '*.xz' -e ssh . $DEST 
fi

echo $(($major + 1)) > .major
echo 0 > .minor

CONTINUE=1
while [ $CONTINUE -ne 0 ]; do
	sudo dpkg --force-all -i ../linux-image-*.deb
	CONTINUE=$?
	[ $CONTINUE -ne 0 ] && sleep 5;
done

# [ $? -ne 0 ] && exit 1
echo $major.$minor >> myversioning

temp=`mktemp XXXXXX`
sudo cat /boot/grub/grub.cfg | while read line; do
	if [[ "$line" = */boot/vmlinuz-3.13.5* ]]; then
		echo "$line" | sed -e 's/quiet/kgdboc=ttyS0,115200 kgdbwait/' >> $temp
		echo $line |  sed -e 's/quiet/kgdboc=ttyS0,115200 kgdbwait/'
	else
		echo "$line" >> $temp
	fi
done

sudo mv $temp /boot/grub/grub.cfg

rm $temp 2> /dev/null

#if [ "$DEST" != "NONE" ]; then
#	wait $PID
#fi

sudo reboot

