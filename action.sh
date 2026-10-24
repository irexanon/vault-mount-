#!/system/bin/sh
# KernelSU "Action" button: show status; lock the vault if it is unlocked.
V=/data/adb/modules/vaultmount/bin/vaultctl
if [ "$($V initialized)" != "yes" ]; then
  echo "No vault yet. Open the WebUI to create one."
elif [ "$($V status)" = "unlocked" ]; then
  $V lock
else
  echo "Vault is locked. Open the WebUI to unlock."
fi
