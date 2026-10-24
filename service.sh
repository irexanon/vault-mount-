#!/system/bin/sh
# Runs at boot. If auto-unlock is on, unlock the vault so allowed apps work immediately.
until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 2; done
mkdir -p /data/adb/vault/plain
/data/adb/modules/vaultmount/bin/vaultctl autounlock
