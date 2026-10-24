#!/system/bin/sh
# Runs at boot (late_start service). The vault stays LOCKED until you run
# `vaultctl unlock`; nothing is mounted automatically.
until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 2; done
mkdir -p /data/adb/vault/plain
