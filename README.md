# VaultMount

KernelSU + Zygisk Next module (Android 15). Gives chosen apps an encrypted
(gocryptfs) storage folder that only they can see, via per-app mount namespaces.

## Install
1. Push to GitHub; the Actions build produces `VaultMount.zip` (Artifacts, or Releases on `v*` tags).
2. Flash in KernelSU Manager, reboot (Zygisk Next on).
3. `su -c "vaultctl init"`  (pick password, once)
4. Open the module's WebUI in KernelSU Manager: unlock, allow apps.
   Or CLI: `su -c "vaultctl unlock"`, `su -c "vaultctl allow <pkg> <target> <sub>"`.
5. Fully restart the allowed app. Debug: `logcat -s VaultMount`.
