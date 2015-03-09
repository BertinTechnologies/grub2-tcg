#! /bin/sh
checklist=/tmp/keys/checklist


echo "UPDATE THE CHECKLIST"
echo "Which kernel is used between the following ones?"
ls /boot/vmlinuz* > /tmp/list
cut -c15- /tmp/list
read version

list="/boot/grub/stage1 /boot/grub/stage2 /boot/config-$version /boot/vmlinuz-$version /boot/initrd.img-$version /boot/System.map-$version"

echo "Do you want to add some modules in the checklist? (y or n)"; read answer
if [ $answer = y ]; then
	echo "Which module?"
	ls /boot/grub/*mod
	read modules
	list="$list $modules"
fi
key="SRK"
echo "number of keys (others than SRK)?"; read nb;
for i in $(seq 1 1 $nb); do
	echo "key" $i"?"; read key;
	list="$list $key"
	listkey="$listkey -k $key"
	echo -n "(hd1,3)" > /tmp/keyy$i
	echo $key"'" > /tmp/keyy
	cut -c6- /tmp/keyy >> /tmp/keyy$i
	echo "Well-known pwd for parent key?(y or n)"; read answer;
	if [ $answer = y ]; then
		touch /tmp/wk$i
	fi
done
echo "Well-known pwd for $key ?(y or n)"; read answer;
wk0=""
if [ $answer = y ]; then
	wk0="-k"
fi

echo 'Computing list '
for i in $list; do
	test -e $i
	echo $i
	shasum $i >> /tmp/sha
done
cut -c1-41,48- /tmp/sha > /tmp/list

/home/cspn/src/tcgutil/tcg_seal $listkey -p 0:1:2:3:4:5:6:7:14 -i /tmp/list -o $checklist


echo "UPDATE THE CONFIGURATION FILE"

configfile=/tmp/conf
checklist="(hd1,3)/keys/checklist"
oslimited="(hd1,3)/keys/failed.cfg"
menu="(hd1,3)/grub/grub.cfg"

echo "set default=\"0\"
set lang=fr
set timeout=5

menuentry 'Demarrage securise' {
root (hd1,3) 
" > $configfile

if [ $nb -gt 0 ]; then
	echo "### Load key(s) used to seal the checklist ###
PKEY='SRK'" >> $configfile
fi

for i in $(seq 1 1 $nb); do
	echo -n "KEY='">> $configfile
	cat /tmp/keyy$i >> $configfile
	echo "echo 'load' \$KEY" >> $configfile
	if test -e /tmp/wk$i ; then
		echo "tpm_loadkey -z \$PKEY \$KEY" >> $configfile
	else	
		echo "tpm_loadkey \$PKEY \$KEY" >> $configfile
	fi
	echo "result=\$?
if [ \$result -ne 0 ]; then
	configfile $oslimited
fi
" >> $configfile
	
	if [ $i != $nb ]; then
		echo -n "PKEY='" >> $configfile
		cat /tmp/keyy$i >> $configfile
	fi
done

echo "
###  Unseal and check the checklist file ###
CHECKLIST='$checklist'
echo \$CHECKLIST 'to unseal'
tpm_checkfile -s $wk0 \$CHECKLIST \$KEY
result=\$?
if [ \$result -ne 0 ]; then
	configfile $oslimited
fi

### If no error appears load the usual Grub menu ###
configfile $menu
}

menuentry 'Demarrage securise (sans rendre le fichier checkfile inaccessible)' {
root (hd1,3) 
" >> $configfile

if [ $nb -gt 0 ]; then
	echo "### Load key(s) used to seal the checklist ###
PKEY='SRK'" >> $configfile
fi

for i in $(seq 1 1 $nb); do
	echo -n "KEY='">> $configfile
	cat /tmp/keyy$i >> $configfile
	echo "echo 'load' \$KEY" >> $configfile
	if test -e /tmp/wk$i ; then
		echo "tpm_loadkey -z \$PKEY \$KEY" >> $configfile
	else	
		echo "tpm_loadkey \$PKEY \$KEY" >> $configfile
	fi
	echo "result=\$?
if [ \$result -ne 0 ]; then
	configfile $oslimited
fi
" >> $configfile
	
	if [ $i != $nb ]; then
		echo -n "PKEY='" >> $configfile
		cat /tmp/keyy$i >> $configfile
	fi
done

echo "
###  Unseal and check the checklist file ###
CHECKLIST='$checklist'
echo \$CHECKLIST 'to unseal'
tpm_checkfile -s $wk0 -a \$CHECKLIST \$KEY
result=\$?
if [ \$result -ne 0 ]; then
	configfile $oslimited
fi

### If no error appears load the usual Grub menu ###
configfile $menu
}
" >> $configfile


wipe -f /tmp/sha /tmp/list /tmp/keyy* /tmp/wk*
exit 0
