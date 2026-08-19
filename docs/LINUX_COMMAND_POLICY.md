# Linux Command Execution Risk Matrix & Agent Policy

## 1. Overview

To prevent unintended destruction, privilege escalation, and unauthorized changes on Linux hosts (Debian, Ubuntu, RHEL, Arch, Alpine, macOS terminals), **Hardening IA** integrates an explicit 4-tier Linux Command Risk Matrix:

| Risk Tier | Operational Classification | Description | Execution Policy |
| :--- | :--- | :--- | :--- |
| 🟢 **Low** | Read-only / Query / Diagnostics | Informational commands that inspect files, system resources, and network status without altering system state. | **Auto-executable without operator prompt.** |
| 🟡 **Medium** | User Operations / File Creation / Modification | Commands that create, edit, move, archive, or process local files and user cron/jobs. | **Requires explicit operator confirmation.** |
| 🟠 **High** | Administrative / Root / Services / Network | Commands executing with `sudo`, managing packages, altering services, modifying permissions, or signaling processes. | **Requires explicit operator confirmation + high-visibility warning.** |
| 🔴 **Critical** | Irreversible Data Loss / Structural Formatting | Destructive block commands, partition table alterations, disk formatters, and pipe-to-shell patterns. | **Strictly prohibited or multi-step confirmation.** |

---

## 2. Command Risk Catalog

### 🟢 Low Risk (Auto-Run Permitted)
- **Filesystem & Navigation:** `ls`, `cd`, `pwd`, `find`, `locate`, `which`, `whereis`, `whatis`, `type`, `file`, `stat`, `tree`, `du`, `df`, `ncdu`, `basename`, `dirname`, `realpath`, `readlink`.
- **Text Viewing & Stream Filters:** `cat`, `tac`, `nl`, `less`, `more`, `head`, `tail`, `grep`, `egrep`, `fgrep`, `rg`, `ripgrep`, `awk`, `cut`, `paste`, `join`, `sort`, `uniq`, `wc`, `tr`, `diff`, `colordiff`, `cmp`, `comm`, `sdiff`, `column`, `fold`, `fmt`, `pr`, `expand`, `unexpand`, `strings`, `hexdump`, `xxd`, `od`, `jq`, `yq`.
- **Process & Performance Monitoring:** `ps`, `top`, `htop`, `btop`, `atop`, `glances`, `pstree`, `pgrep`, `pidof`, `jobs`, `wait`, `watch`, `time`, `fuser`, `lsof`, `free`, `vmstat`, `iostat`, `mpstat`, `sar`, `dstat`, `uptime`, `strace`, `ltrace`.
- **Systemd & Logging Diagnostics:** `journalctl`, `systemd-analyze`, `systemd-cgls`, `systemd-cgtop`.
- **Network Queries & Diagnostics:** `ping`, `ping6`, `traceroute`, `tracepath`, `mtr`, `netstat`, `ss`, `dig`, `nslookup`, `host`, `whois`, `curl`, `wget`, `telnet`, `iperf`, `iperf3`, `speedtest-cli`.
- **Disks & Storage Diagnostics:** `lsblk`, `blkid`, `findmnt`, `sync`, `smartctl`, `pvs`, `vgs`, `lvs`.
- **Hardware & Kernel Information:** `uname`, `lscpu`, `lshw`, `lspci`, `lsusb`, `dmidecode`, `inxi`, `hwinfo`, `sensors`, `dmesg`, `lsmod`, `modinfo`, `logger`.
- **Security & Integrity Checks:** `ssh-agent`, `sha256sum`, `sha512sum`, `sha1sum`, `md5sum`, `cksum`, `b2sum`, `aa-status`, `ausearch`, `aureport`, `lynis`, `clamscan`, `rkhunter`, `chkrootkit`.
- **Shell Builtins & Utilities:** `bash`, `sh`, `zsh`, `dash`, `env`, `export`, `alias`, `unalias`, `history`, `clear`, `reset`, `echo`, `printf`, `read`, `screen`, `tmux`, `byobu`, `atq`, `script`, `scriptreplay`, `date`, `cal`, `bc`, `dc`, `seq`, `yes`, `sleep`, `expr`, `test`.

---

### 🟡 Medium Risk (Operator Approval Required)
- **Filesystem Creation & Mutation:** `mkdir`, `rmdir`, `cp`, `mv`, `touch`, `ln`, `updatedb`, `mktemp`, `rename`, `install`.
- **Stream & File Editors:** `sed` (with `-i`), `patch`, `tee`, `xargs`, `split`, `csplit`, `nano`, `vim`, `vi`, `micro`, `emacs`.
- **Packaging Helpers:** `dpkg-deb`, `flatpak`.
- **Process Scheduling & Backgrounding:** `nice`, `nohup`, `disown`, `bg`, `fg`, `timeout`, `valgrind`, `crontab`, `at`, `atrm`, `anacron`.
- **Network Relays & Transfers:** `nc`, `netcat`, `socat`, `nmap`, `scp`, `sftp`, `rsync`, `ftp`, `resolvectl`.
- **Archiving & Compression:** `tar`, `gzip`, `gunzip`, `bzip2`, `bunzip2`, `xz`, `unxz`, `zip`, `unzip`, `7z`, `zstd`, `unzstd`, `cpio`, `dump`, `borg`, `restic`.
- **Key Generation & Crypto:** `ssh-keygen`, `ssh-copy-id`, `ssh-add`, `gpg`, `gpg2`, `openssl`.
- **Shell Execution Wrappers:** `source`, `exec`, `eval`.

---

### 🟠 High Risk (Admin Approval + Warning Required)
- **Privilege Escalation:** `sudo`, `su`, `doas`.
- **File Deletion & Shredding:** `rm`, `shred`.
- **Package Management:** `apt`, `apt-get`, `apt-mark`, `apt-key`, `apt-cdrom`, `aptitude`, `dpkg`, `dpkg-reconfigure`, `dpkg-statoverride`, `add-apt-repository`, `ppa-purge`, `snap`, `tasksel`, `update-alternatives`, `debootstrap`, `alien`, `debconf-set-selections`.
- **User & Group Administration:** `useradd`, `adduser`, `usermod`, `userdel`, `deluser`, `groupadd`, `addgroup`, `groupmod`, `groupdel`, `delgroup`, `passwd`, `chpasswd`, `gpasswd`, `chage`, `vipw`, `vigr`, `visudo`.
- **Permissions & ACLs:** `chmod`, `chown`, `chgrp`, `setfacl`, `chattr`.
- **Process Termination & Stress:** `kill`, `pkill`, `killall`, `renice`, `taskset`, `stress`, `stress-ng`.
- **System Services & State Control:** `systemctl`, `hostnamectl`, `timedatectl`, `localectl`, `loginctl`, `systemd-nspawn`, `systemd-run`, `service`, `update-rc.d`, `invoke-rc.d`, `init`, `telinit`, `shutdown`, `reboot`, `poweroff`, `halt`.
- **Network Configuration & Firewalls:** `ip`, `ifconfig`, `iwconfig`, `iw`, `route`, `arp`, `tcpdump`, `tshark`, `iptables`, `ip6tables`, `nft`, `ufw`, `firewalld`, `ethtool`, `mii-tool`, `nmcli`, `nmtui`, `dhclient`, `dhcpcd`, `bridge`, `brctl`, `wg`, `wg-quick`, `openvpn`.
- **Filesystem & Partition Management:** `mount`, `umount`, `tune2fs`, `resize2fs`, `badblocks`, `hdparm`, `nvme`, `losetup`, `swapon`, `swapoff`, `vgcreate`, `lvcreate`, `lvextend`, `restore`.
- **Kernel, Modules & Boot:** `modprobe`, `insmod`, `rmmod`, `depmod`, `sysctl`, `update-initramfs`, `update-grub`.
- **Security Daemons:** `aa-enforce`, `aa-complain`, `aa-disable`, `auditctl`, `fail2ban-client`.

---

### 🔴 Critical Risk (Destructive / Prohibited Anti-Patterns)
- `rm -rf /` or `rm -rf /*`
- Fork Bomb: `:(){ :|:& };:`
- Raw Block Overwrites: `dd if=/dev/zero of=/dev/sd*`, `dd if=/dev/urandom of=/dev/sd*`, `> /dev/sd*`
- Disk Formatting: `mkfs`, `mkfs.ext4`, `mkfs.btrfs`, `mkfs.xfs`, `mkfs.vfat`, `mkfs.ntfs`, `mkswap`
- Partition Table Destruction: `fdisk`, `gdisk`, `parted`, `cfdisk`, `sfdisk`, `wipefs`
- Volume Shrinkage: `lvreduce`
- Integrity Corruptions: `chmod -R 777 /`, `chown -R nobody /`, `mv / /dev/null`
- Remote Untrusted Execution: `wget ... | sh`, `curl ... | bash`
