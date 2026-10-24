#!/system/bin/sh
# KernelSU module installer
ui_print "- VaultMount: preparing vault directories"

V=/data/adb/vault
mkdir -p $V/cipher $V/plain $V/bin
chmod 700 $V
touch $V/rules.conf
chmod 600 $V/rules.conf

# Bundled gocryptfs (built by CI) -> vault dir
if [ -f $MODPATH/bin/gocryptfs ]; then
  cp -f $MODPATH/bin/gocryptfs $V/bin/gocryptfs
  chmod 755 $V/bin/gocryptfs
fi
# Put vaultctl on the root shell PATH
mkdir -p /data/adb/ksu/bin
cp -f $MODPATH/bin/vaultctl /data/adb/ksu/bin/vaultctl
chmod 755 /data/adb/ksu/bin/vaultctl

if [ ! -x $V/bin/gocryptfs ]; then
  ui_print "! gocryptfs binary not found."
  ui_print "  Put an arm64 static gocryptfs at:"
  ui_print "  $V/bin/gocryptfs  (chmod 755)"
fi

ui_print "- Requires Zygisk Next enabled."
ui_print "- Next: su -c vaultctl init   (after reboot)"
set_perm_recursive $MODPATH 0 0 0755 0644
set_perm $MODPATH/bin/vaultctl 0 0 0755
[ -f $MODPATH/bin/gocryptfs ] && set_perm $MODPATH/bin/gocryptfs 0 0 0755
set_perm $MODPATH/service.sh 0 0 0755
