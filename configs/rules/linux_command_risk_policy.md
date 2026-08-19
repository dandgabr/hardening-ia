# Linux Terminal Command Execution Security Policy & Risk Matrix

## Mandatory Operational Principle
When interacting with a Linux shell (Debian, Ubuntu, RHEL, Arch, Alpine, macOS bash/zsh), you MUST adhere to the following command execution rules based on operational risk levels:

---

## 🟢 Level 1: Low Risk (Auto-Executable / Inspection & Diagnostics)
> **Rule:** You are permitted to execute these commands without requesting manual operator confirmation, provided they do not pipe output into destructive commands.

**Scope of Commands:**
- **Navigation & Inspection:** `ls`, `cd`, `pwd`, `find`, `which`, `whereis`, `whatis`, `type`, `file`, `stat`, `tree`, `basename`, `dirname`, `realpath`, `readlink`, `du`, `df`, `ncdu`.
- **Text Reading & Filtering:** `cat`, `tac`, `nl`, `less`, `more`, `head`, `tail`, `grep`, `egrep`, `fgrep`, `rg`, `ripgrep`, `awk`, `cut`, `paste`, `join`, `sort`, `uniq`, `wc`, `tr`, `diff`, `colordiff`, `cmp`, `comm`, `sdiff`, `column`, `fold`, `fmt`, `pr`, `expand`, `unexpand`, `strings`, `hexdump`, `xxd`, `od`, `jq`, `yq`.
- **System & Process Diagnostics:** `ps`, `top`, `htop`, `btop`, `pstree`, `pgrep`, `pidof`, `jobs`, `wait`, `watch`, `time`, `fuser`, `lsof`, `free`, `vmstat`, `iostat`, `mpstat`, `sar`, `dstat`, `uptime`, `strace`, `ltrace`, `journalctl`, `systemd-analyze`, `dmesg`, `lsmod`, `modinfo`.
- **Network Queries:** `ping`, `ping6`, `traceroute`, `tracepath`, `mtr`, `netstat`, `ss`, `dig`, `nslookup`, `host`, `whois`, `curl`, `wget`, `telnet`, `iperf`, `speedtest-cli`.
- **Hardware & Disks Query:** `lsblk`, `blkid`, `findmnt`, `sync`, `smartctl`, `uname`, `lscpu`, `lshw`, `lspci`, `lsusb`, `dmidecode`, `sensors`.
- **Identity & Security Query:** `id`, `whoami`, `who`, `w`, `users`, `getfacl`, `lsattr`, `aa-status`, `ausearch`, `aureport`, `lynis`, `clamscan`, `rkhunter`, `sha256sum`, `sha512sum`, `md5sum`.
- **Shell Basics & Env:** `echo`, `printf`, `read`, `date`, `cal`, `bc`, `seq`, `yes`, `sleep`, `expr`, `test`, `env`, `export`, `alias`, `history`, `clear`.
- **Version Control Queries:** `git status`, `git log`, `git diff`, `git branch`, `git show`.

---

## 🟡 Level 2: Medium Risk (Local User Operations & File Modifications)
> **Rule:** You MUST prompt the operator and require confirmation before executing any command in this tier.

**Scope of Commands:**
- **Local File & Directory Mutations:** `mkdir`, `rmdir`, `cp`, `mv`, `touch`, `ln`, `mktemp`, `rename`, `install`, `sed` (with `-i`), `patch`, `tee`, `xargs`, `split`, `csplit`.
- **Interactive Editors & Tools:** `nano`, `vim`, `vi`, `micro`, `emacs`.
- **Compression & Archiving:** `tar`, `gzip`, `gunzip`, `bzip2`, `bunzip2`, `xz`, `unxz`, `zip`, `unzip`, `7z`, `zstd`, `unzstd`, `cpio`, `dump`, `borg`, `restic`.
- **Job & Session Control:** `nice`, `nohup`, `disown`, `bg`, `fg`, `timeout`, `crontab`, `at`, `anacron`.
- **Key & Crypto Generation:** `ssh-keygen`, `ssh-copy-id`, `ssh-add`, `gpg`, `openssl`.
- **Network Sockets & Transfers:** `nc`, `netcat`, `socat`, `nmap`, `scp`, `sftp`, `rsync`, `ftp`.
- **Version Control Changes:** `git add`, `git commit`, `git checkout`, `git switch`, `git stash`, `git merge`, `git pull`, `git push`.

---

## 🟠 Level 3: High Risk (Administrative, Sudo, Package Management, Services)
> **Rule:** You MUST display a high-visibility warning and require explicit operator confirmation before executing.

**Scope of Commands:**
- **Superuser Elevation:** `sudo`, `su`, `doas`.
- **File Deletion:** `rm`, `shred`.
- **Permissions & Ownership:** `chmod`, `chown`, `chgrp`, `setfacl`, `chattr`, `vipw`, `vigr`, `visudo`.
- **User & Group Administration:** `useradd`, `adduser`, `usermod`, `userdel`, `deluser`, `groupadd`, `addgroup`, `groupmod`, `groupdel`, `passwd`, `chpasswd`, `gpasswd`, `chage`.
- **Package Management:** `apt`, `apt-get`, `apt-mark`, `apt-key`, `apt-cdrom`, `aptitude`, `dpkg`, `dpkg-reconfigure`, `dpkg-statoverride`, `add-apt-repository`, `ppa-purge`, `snap`, `tasksel`, `update-alternatives`, `debootstrap`, `alien`.
- **Process Signals:** `kill`, `pkill`, `killall`, `renice`, `taskset`, `stress`, `stress-ng`.
- **System Services & State:** `systemctl`, `service`, `update-rc.d`, `invoke-rc.d`, `init`, `telinit`, `shutdown`, `reboot`, `poweroff`, `halt`, `hostnamectl`, `timedatectl`, `localectl`, `loginctl`, `systemd-nspawn`, `systemd-run`.
- **Network Interfaces & Firewall:** `ip`, `ifconfig`, `iwconfig`, `iw`, `route`, `arp`, `tcpdump`, `tshark`, `iptables`, `ip6tables`, `nft`, `ufw`, `firewalld`, `ethtool`, `mii-tool`, `nmcli`, `nmtui`, `dhclient`, `dhcpcd`, `bridge`, `brctl`, `wg`, `openvpn`.
- **Kernel & Modules:** `modprobe`, `insmod`, `rmmod`, `depmod`, `sysctl`, `update-initramfs`, `update-grub`.
- **Storage & Volume Management:** `mount`, `umount`, `tune2fs`, `resize2fs`, `badblocks`, `hdparm`, `nvme`, `losetup`, `swapon`, `swapoff`, `vgcreate`, `lvcreate`, `lvextend`, `restore`.
- **Security Daemons:** `aa-enforce`, `aa-complain`, `aa-disable`, `auditctl`, `fail2ban-client`.

---

## 🔴 Level 4: Critical Risk (Destructive / Irreversible Anti-Patterns)
> **Rule:** PROHIBITED by default. In extreme development maintenance, requires strict multi-step confirmation and safety checks.

**Forbidden Commands & Patterns:**
- `rm -rf /` or `rm -rf /*` (Entire root filesystem deletion)
- `:(){ :|:& };:` (Fork Bomb denial of service)
- `dd if=/dev/zero of=/dev/sd*` or `dd if=/dev/urandom of=/dev/sd*` (Raw disk overwrites)
- `mkfs`, `mkfs.ext4`, `mkfs.btrfs`, `mkfs.xfs`, `mkfs.vfat`, `mkfs.ntfs`, `mkswap` (Disk partition formatting)
- `fdisk`, `gdisk`, `parted`, `cfdisk`, `sfdisk`, `wipefs` (Partition table destruction)
- `lvreduce` (Logical volume shrinkage without filesystem verification)
- `> /dev/sd*` (Direct disk block corruption)
- `chmod -R 777 /` or `chown -R nobody /` (System-wide permission destruction)
- `curl ... | bash` or `wget ... | sh` (Uninspected remote pipe-to-shell execution)
