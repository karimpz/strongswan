#!/bin/sh

DIR="/etc/pts"
OVAL_DIR="$DIR/oval"
DATE=`date +%Y%m%d-%H%M`
UBUNTU="https://people.canonical.com/~ubuntu-security/oval"
UBUNTU_VERSIONS="bionic xenial"
DEBIAN="https://www.debian.org/security/oval"
DEBIAN_VERSIONS="stretch jessie wheezy"
CMD=/usr/sbin/oval-updater
CMD_LOG="$DIR/logs/$DATE-oval-update.log"
DEL_LOG=1

mkdir -p $OVAL_DIR
cd $OVAL_DIR

# Download Ubuntu OVAL files

for v in $UBUNTU_VERSIONS
do
  wget -nv $UBUNTU/com.ubuntu.$v.cve.oval.xml -O $v-oval.xml
done

# Download Debian distribution information

for v in $DEBIAN_VERSIONS
do
  wget -nv $DEBIAN/oval-definitions-$v.xml -O $v-oval.xml
done

# Run oval-updater

#  echo "security: $f"
#  $CMD --os "Ubuntu 18.04" --arch "x86_64" --file $f --security \
#       --uri $UBUNTU >> $CMD_LOG 2>&1
#  if [ $? -eq 0 ]
#  then
#    DEL_LOG=0
#  fi

# Delete log file if no security updates were found

if [ $DEL_LOG -eq 1 ]
then
  rm $CMD_LOG
  echo "no new vulnerabilities found"
fi
