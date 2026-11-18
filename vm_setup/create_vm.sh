#!/usr/bin/env bash
# Run on the WINDOWS host (Git Bash) AFTER the Ubuntu ISO finished downloading.
# Creates an Ubuntu 24.04 VM and kicks off an UNATTENDED headless install via
# VBoxManage (no GUI clicking). Sets a NAT port-forward so we can SSH in to
# provision Docker + the pentest lab afterward.
#
# This is the agent-experiment host VM for the Cochise + AutoPenBench stage.
# GPU is NOT available inside the VM; the agents' LLM "brain" calls the HOST
# Ollama over the NAT gateway (10.0.2.2), while attack traffic stays isolated.
set -euo pipefail

VBOX="/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
VM="pentest-lab"
ISO="/c/vm_iso/ubuntu-24.04.5-live-server-amd64.iso"
DISK="/c/Users/user/VirtualBox VMs/${VM}/${VM}.vdi"
LAB_USER="lab"
LAB_PASS="labpass"            # throwaway credential for an isolated lab VM only
SSH_HOST_PORT=2222            # host:2222 -> guest:22

[ -f "$ISO" ] || { echo "ISO not found yet: $ISO (wait for download)"; exit 1; }

echo "[*] (re)create VM $VM"
"$VBOX" unregistervm "$VM" --delete 2>/dev/null || true
"$VBOX" createvm --name "$VM" --ostype Ubuntu_64 --register
"$VBOX" modifyvm "$VM" --memory 8192 --cpus 4 --firmware efi \
  --nic1 nat --graphicscontroller vmsvga --vram 32 --audio-driver none
# SSH port-forward on the NAT adapter
"$VBOX" modifyvm "$VM" --natpf1 "ssh,tcp,127.0.0.1,${SSH_HOST_PORT},,22"

echo "[*] create 60GB disk + attach"
"$VBOX" createmedium disk --filename "$DISK" --size 61440 --format VDI
"$VBOX" storagectl "$VM" --name SATA --add sata --controller IntelAhci --portcount 2
"$VBOX" storageattach "$VM" --storagectl SATA --port 0 --device 0 --type hdd --medium "$DISK"

echo "[*] start UNATTENDED headless install (subiquity autoinstall; ~15-30 min)"
"$VBOX" unattended install "$VM" \
  --iso="$ISO" \
  --user="$LAB_USER" --password="$LAB_PASS" --full-user-name="lab user" \
  --install-additions --time-zone="Asia/Seoul" --locale="en_US" \
  --post-install-command="apt-get -y install openssh-server || true" \
  --start-vm=headless

cat <<EOF

[KICKED OFF] Unattended install running headless. It will install Ubuntu, reboot,
and (via post-install) ensure openssh-server. Give it ~15-30 min.

When it is up, SSH in from Windows and provision Docker:
  ssh -p ${SSH_HOST_PORT} ${LAB_USER}@127.0.0.1          # password: ${LAB_PASS}
  # copy provision_vm.sh in, then:
  chmod +x provision_vm.sh && ./provision_vm.sh

Check VM state any time:
  "$VBOX" list runningvms
  "$VBOX" showvminfo ${VM} --machinereadable | grep -i VMState
EOF
