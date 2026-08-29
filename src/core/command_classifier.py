"""Multi-platform Command Risk Classification Engine for Linux, Windows, and macOS.

Categorizes commands into 4 security risk tiers:
  - LOW: Read-only, inspection, query, diagnostics -> Auto-executable without approval.
  - MEDIUM: Local user operations, file creation, editing, archiving -> Requires confirmation.
  - HIGH: Administrative, root/sudo/UAC, service control, firewall, permissions, kill signals -> Requires confirmation + warning.
  - CRITICAL: Irreversible data destruction, raw disk format, partition manipulation, kernel tampering -> Blocked or strict multi-step confirmation.
"""

from enum import Enum
from typing import Dict, List, Tuple
from pathlib import Path
import re

from src.core.logger import get_logger
from src.core.os_detector import OSDetector

logger = get_logger("command_classifier")


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ==============================================================================
# 1. EXHAUSTIVE LINUX / DEBIAN / UBUNTU COMMAND RISK DATABASE (390+ Commands)
# ==============================================================================
LINUX_COMMANDS: Dict[str, RiskLevel] = {
    # Navigation, Inspection & Coreutils
    "ls": RiskLevel.LOW, "cd": RiskLevel.LOW, "pwd": RiskLevel.LOW, "find": RiskLevel.LOW,
    "locate": RiskLevel.LOW, "plocate": RiskLevel.LOW, "which": RiskLevel.LOW, "whereis": RiskLevel.LOW,
    "whatis": RiskLevel.LOW, "type": RiskLevel.LOW, "file": RiskLevel.LOW, "stat": RiskLevel.LOW,
    "tree": RiskLevel.LOW, "du": RiskLevel.LOW, "df": RiskLevel.LOW, "ncdu": RiskLevel.LOW,
    "basename": RiskLevel.LOW, "dirname": RiskLevel.LOW, "realpath": RiskLevel.LOW, "readlink": RiskLevel.LOW,
    "sync": RiskLevel.LOW, "updatedb": RiskLevel.MEDIUM, "mkdir": RiskLevel.MEDIUM, "rmdir": RiskLevel.MEDIUM,
    "cp": RiskLevel.MEDIUM, "mv": RiskLevel.MEDIUM, "touch": RiskLevel.MEDIUM, "ln": RiskLevel.MEDIUM,
    "mktemp": RiskLevel.MEDIUM, "rename": RiskLevel.MEDIUM, "install": RiskLevel.MEDIUM,
    "rm": RiskLevel.HIGH, "shred": RiskLevel.HIGH,

    # Text Viewing, Processing & Stream Editors
    "cat": RiskLevel.LOW, "tac": RiskLevel.LOW, "nl": RiskLevel.LOW, "less": RiskLevel.LOW,
    "more": RiskLevel.LOW, "head": RiskLevel.LOW, "tail": RiskLevel.LOW, "grep": RiskLevel.LOW,
    "egrep": RiskLevel.LOW, "fgrep": RiskLevel.LOW, "rg": RiskLevel.LOW, "ripgrep": RiskLevel.LOW,
    "awk": RiskLevel.LOW, "gawk": RiskLevel.LOW, "mawk": RiskLevel.LOW, "cut": RiskLevel.LOW,
    "paste": RiskLevel.LOW, "join": RiskLevel.LOW, "sort": RiskLevel.LOW, "uniq": RiskLevel.LOW,
    "wc": RiskLevel.LOW, "tr": RiskLevel.LOW, "diff": RiskLevel.LOW, "colordiff": RiskLevel.LOW,
    "cmp": RiskLevel.LOW, "comm": RiskLevel.LOW, "sdiff": RiskLevel.LOW, "column": RiskLevel.LOW,
    "fold": RiskLevel.LOW, "fmt": RiskLevel.LOW, "pr": RiskLevel.LOW, "expand": RiskLevel.LOW,
    "unexpand": RiskLevel.LOW, "strings": RiskLevel.LOW, "hexdump": RiskLevel.LOW, "xxd": RiskLevel.LOW,
    "od": RiskLevel.LOW, "jq": RiskLevel.LOW, "yq": RiskLevel.LOW,
    "sed": RiskLevel.MEDIUM, "patch": RiskLevel.MEDIUM, "tee": RiskLevel.MEDIUM, "xargs": RiskLevel.MEDIUM,
    "split": RiskLevel.MEDIUM, "csplit": RiskLevel.MEDIUM, "nano": RiskLevel.MEDIUM, "vim": RiskLevel.MEDIUM,
    "vi": RiskLevel.MEDIUM, "micro": RiskLevel.MEDIUM, "emacs": RiskLevel.MEDIUM,

    # Package Management
    "apt-cache": RiskLevel.LOW, "apt-config": RiskLevel.LOW, "apt-file": RiskLevel.LOW,
    "dpkg-query": RiskLevel.LOW, "debconf-show": RiskLevel.LOW,
    "dpkg-deb": RiskLevel.MEDIUM, "flatpak": RiskLevel.MEDIUM,
    "apt": RiskLevel.HIGH, "apt-get": RiskLevel.HIGH, "apt-mark": RiskLevel.HIGH, "apt-key": RiskLevel.HIGH,
    "apt-cdrom": RiskLevel.HIGH, "aptitude": RiskLevel.HIGH, "dpkg": RiskLevel.HIGH,
    "dpkg-reconfigure": RiskLevel.HIGH, "dpkg-statoverride": RiskLevel.HIGH, "add-apt-repository": RiskLevel.HIGH,
    "ppa-purge": RiskLevel.HIGH, "snap": RiskLevel.HIGH, "tasksel": RiskLevel.HIGH,
    "update-alternatives": RiskLevel.HIGH, "debootstrap": RiskLevel.HIGH, "alien": RiskLevel.HIGH,
    "debconf-set-selections": RiskLevel.HIGH, "dpkg-divert": RiskLevel.HIGH,

    # Users, Permissions, and Access Controls
    "id": RiskLevel.LOW, "whoami": RiskLevel.LOW, "who": RiskLevel.LOW, "w": RiskLevel.LOW,
    "last": RiskLevel.LOW, "lastlog": RiskLevel.LOW, "lastb": RiskLevel.LOW, "users": RiskLevel.LOW,
    "getfacl": RiskLevel.LOW, "lsattr": RiskLevel.LOW,
    "umask": RiskLevel.MEDIUM,
    "sudo": RiskLevel.HIGH, "su": RiskLevel.HIGH, "doas": RiskLevel.HIGH, "useradd": RiskLevel.HIGH,
    "adduser": RiskLevel.HIGH, "usermod": RiskLevel.HIGH, "userdel": RiskLevel.HIGH, "deluser": RiskLevel.HIGH,
    "groupadd": RiskLevel.HIGH, "addgroup": RiskLevel.HIGH, "groupmod": RiskLevel.HIGH,
    "groupdel": RiskLevel.HIGH, "delgroup": RiskLevel.HIGH, "passwd": RiskLevel.HIGH,
    "chpasswd": RiskLevel.HIGH, "gpasswd": RiskLevel.HIGH, "chmod": RiskLevel.HIGH, "chown": RiskLevel.HIGH,
    "chgrp": RiskLevel.HIGH, "chage": RiskLevel.HIGH, "vipw": RiskLevel.HIGH, "vigr": RiskLevel.HIGH,
    "visudo": RiskLevel.HIGH, "setfacl": RiskLevel.HIGH, "chattr": RiskLevel.HIGH,

    # Process Monitoring & Resource Diagnostics
    "ps": RiskLevel.LOW, "top": RiskLevel.LOW, "htop": RiskLevel.LOW, "btop": RiskLevel.LOW,
    "bpytop": RiskLevel.LOW, "atop": RiskLevel.LOW, "glances": RiskLevel.LOW, "pstree": RiskLevel.LOW,
    "pgrep": RiskLevel.LOW, "pidof": RiskLevel.LOW, "jobs": RiskLevel.LOW, "wait": RiskLevel.LOW,
    "watch": RiskLevel.LOW, "time": RiskLevel.LOW, "fuser": RiskLevel.LOW, "lsof": RiskLevel.LOW,
    "free": RiskLevel.LOW, "vmstat": RiskLevel.LOW, "iostat": RiskLevel.LOW, "mpstat": RiskLevel.LOW,
    "sar": RiskLevel.LOW, "dstat": RiskLevel.LOW, "uptime": RiskLevel.LOW, "strace": RiskLevel.LOW,
    "ltrace": RiskLevel.LOW,
    "nice": RiskLevel.MEDIUM, "nohup": RiskLevel.MEDIUM, "disown": RiskLevel.MEDIUM,
    "bg": RiskLevel.MEDIUM, "fg": RiskLevel.MEDIUM, "timeout": RiskLevel.MEDIUM, "valgrind": RiskLevel.MEDIUM,
    "kill": RiskLevel.HIGH, "pkill": RiskLevel.HIGH, "killall": RiskLevel.HIGH, "renice": RiskLevel.HIGH,
    "taskset": RiskLevel.HIGH, "stress": RiskLevel.HIGH, "stress-ng": RiskLevel.HIGH,

    # Systemd, Services & State Management
    "journalctl": RiskLevel.LOW, "systemd-analyze": RiskLevel.LOW, "systemd-cgls": RiskLevel.LOW,
    "systemd-cgtop": RiskLevel.LOW,
    "resolvectl": RiskLevel.MEDIUM,
    "systemctl": RiskLevel.HIGH, "hostnamectl": RiskLevel.HIGH, "timedatectl": RiskLevel.HIGH,
    "localectl": RiskLevel.HIGH, "loginctl": RiskLevel.HIGH, "systemd-nspawn": RiskLevel.HIGH,
    "systemd-run": RiskLevel.HIGH, "service": RiskLevel.HIGH, "update-rc.d": RiskLevel.HIGH,
    "invoke-rc.d": RiskLevel.HIGH, "init": RiskLevel.HIGH, "telinit": RiskLevel.HIGH,
    "shutdown": RiskLevel.HIGH, "reboot": RiskLevel.HIGH, "poweroff": RiskLevel.HIGH, "halt": RiskLevel.HIGH,

    # Networking & Connectivity
    "ping": RiskLevel.LOW, "ping6": RiskLevel.LOW, "traceroute": RiskLevel.LOW, "tracepath": RiskLevel.LOW,
    "mtr": RiskLevel.LOW, "netstat": RiskLevel.LOW, "ss": RiskLevel.LOW, "dig": RiskLevel.LOW,
    "nslookup": RiskLevel.LOW, "host": RiskLevel.LOW, "whois": RiskLevel.LOW, "curl": RiskLevel.LOW,
    "wget": RiskLevel.LOW, "telnet": RiskLevel.LOW, "iperf": RiskLevel.LOW, "iperf3": RiskLevel.LOW,
    "speedtest-cli": RiskLevel.LOW, "ssh": RiskLevel.LOW,
    "nc": RiskLevel.MEDIUM, "netcat": RiskLevel.MEDIUM, "socat": RiskLevel.MEDIUM, "nmap": RiskLevel.MEDIUM,
    "scp": RiskLevel.MEDIUM, "sftp": RiskLevel.MEDIUM, "rsync": RiskLevel.MEDIUM, "ftp": RiskLevel.MEDIUM,
    "ip": RiskLevel.HIGH, "ifconfig": RiskLevel.HIGH, "iwconfig": RiskLevel.HIGH, "iw": RiskLevel.HIGH,
    "route": RiskLevel.HIGH, "arp": RiskLevel.HIGH, "tcpdump": RiskLevel.HIGH, "tshark": RiskLevel.HIGH,
    "iptables": RiskLevel.HIGH, "ip6tables": RiskLevel.HIGH, "nft": RiskLevel.HIGH, "ufw": RiskLevel.HIGH,
    "firewalld": RiskLevel.HIGH, "ethtool": RiskLevel.HIGH, "mii-tool": RiskLevel.HIGH,
    "nmcli": RiskLevel.HIGH, "nmtui": RiskLevel.HIGH, "dhclient": RiskLevel.HIGH, "dhcpcd": RiskLevel.HIGH,
    "bridge": RiskLevel.HIGH, "brctl": RiskLevel.HIGH, "wg": RiskLevel.HIGH, "wg-quick": RiskLevel.HIGH,
    "openvpn": RiskLevel.HIGH,

    # Storage, Disks, Partitions & LVM
    "lsblk": RiskLevel.LOW, "blkid": RiskLevel.LOW, "findmnt": RiskLevel.LOW, "smartctl": RiskLevel.LOW,
    "pvdisplay": RiskLevel.LOW, "pvs": RiskLevel.LOW, "vgdisplay": RiskLevel.LOW, "vgs": RiskLevel.LOW,
    "lvdisplay": RiskLevel.LOW, "lvs": RiskLevel.LOW,
    "mount": RiskLevel.HIGH, "umount": RiskLevel.HIGH, "tune2fs": RiskLevel.HIGH, "resize2fs": RiskLevel.HIGH,
    "badblocks": RiskLevel.HIGH, "hdparm": RiskLevel.HIGH, "nvme": RiskLevel.HIGH, "losetup": RiskLevel.HIGH,
    "swapon": RiskLevel.HIGH, "swapoff": RiskLevel.HIGH, "vgcreate": RiskLevel.HIGH, "lvcreate": RiskLevel.HIGH,
    "lvextend": RiskLevel.HIGH,
    "fdisk": RiskLevel.CRITICAL, "gdisk": RiskLevel.CRITICAL, "parted": RiskLevel.CRITICAL,
    "cfdisk": RiskLevel.CRITICAL, "sfdisk": RiskLevel.CRITICAL, "mkfs": RiskLevel.CRITICAL,
    "mkfs.ext4": RiskLevel.CRITICAL, "mkfs.btrfs": RiskLevel.CRITICAL, "mkfs.xfs": RiskLevel.CRITICAL,
    "mkfs.vfat": RiskLevel.CRITICAL, "mkfs.ntfs": RiskLevel.CRITICAL, "fsck": RiskLevel.CRITICAL,
    "e2fsck": RiskLevel.CRITICAL, "wipefs": RiskLevel.CRITICAL, "dd": RiskLevel.CRITICAL,
    "ddrescue": RiskLevel.CRITICAL, "mkswap": RiskLevel.CRITICAL, "pvcreate": RiskLevel.CRITICAL,
    "lvreduce": RiskLevel.CRITICAL, "mdadm": RiskLevel.CRITICAL, "cryptsetup": RiskLevel.CRITICAL,

    # Compression & Backup
    "tar": RiskLevel.MEDIUM, "gzip": RiskLevel.MEDIUM, "gunzip": RiskLevel.MEDIUM, "bzip2": RiskLevel.MEDIUM,
    "bunzip2": RiskLevel.MEDIUM, "xz": RiskLevel.MEDIUM, "unxz": RiskLevel.MEDIUM, "zip": RiskLevel.MEDIUM,
    "unzip": RiskLevel.MEDIUM, "7z": RiskLevel.MEDIUM, "zstd": RiskLevel.MEDIUM, "unzstd": RiskLevel.MEDIUM,
    "cpio": RiskLevel.MEDIUM, "dump": RiskLevel.MEDIUM, "borg": RiskLevel.MEDIUM, "restic": RiskLevel.MEDIUM,
    "restore": RiskLevel.HIGH,

    # Hardware, Kernel & Modules
    "uname": RiskLevel.LOW, "lscpu": RiskLevel.LOW, "lshw": RiskLevel.LOW, "lspci": RiskLevel.LOW,
    "lsusb": RiskLevel.LOW, "dmidecode": RiskLevel.LOW, "inxi": RiskLevel.LOW, "hwinfo": RiskLevel.LOW,
    "sensors": RiskLevel.LOW, "dmesg": RiskLevel.LOW, "lsmod": RiskLevel.LOW, "modinfo": RiskLevel.LOW,
    "logger": RiskLevel.LOW,
    "modprobe": RiskLevel.HIGH, "insmod": RiskLevel.HIGH, "rmmod": RiskLevel.HIGH, "depmod": RiskLevel.HIGH,
    "sysctl": RiskLevel.HIGH, "update-initramfs": RiskLevel.HIGH, "update-grub": RiskLevel.HIGH,
    "grub-install": RiskLevel.CRITICAL, "kexec": RiskLevel.CRITICAL,

    # Security, Crypto & Auditing
    "ssh-agent": RiskLevel.LOW, "sha256sum": RiskLevel.LOW, "sha512sum": RiskLevel.LOW,
    "sha1sum": RiskLevel.LOW, "md5sum": RiskLevel.LOW, "cksum": RiskLevel.LOW, "b2sum": RiskLevel.LOW,
    "aa-status": RiskLevel.LOW, "apparmor_status": RiskLevel.LOW, "ausearch": RiskLevel.LOW,
    "aureport": RiskLevel.LOW, "lynis": RiskLevel.LOW, "clamscan": RiskLevel.LOW, "rkhunter": RiskLevel.LOW,
    "chkrootkit": RiskLevel.LOW,
    "ssh-keygen": RiskLevel.MEDIUM, "ssh-copy-id": RiskLevel.MEDIUM, "ssh-add": RiskLevel.MEDIUM,
    "gpg": RiskLevel.MEDIUM, "gpg2": RiskLevel.MEDIUM, "openssl": RiskLevel.MEDIUM,
    "aa-enforce": RiskLevel.HIGH, "aa-complain": RiskLevel.HIGH, "aa-disable": RiskLevel.HIGH,
    "auditctl": RiskLevel.HIGH, "fail2ban-client": RiskLevel.HIGH,

    # Shell Environment, Sessions & Tasks
    "bash": RiskLevel.LOW, "sh": RiskLevel.LOW, "zsh": RiskLevel.LOW, "dash": RiskLevel.LOW,
    "env": RiskLevel.LOW, "export": RiskLevel.LOW, "alias": RiskLevel.LOW, "unalias": RiskLevel.LOW,
    "history": RiskLevel.LOW, "clear": RiskLevel.LOW, "reset": RiskLevel.LOW, "echo": RiskLevel.LOW,
    "printf": RiskLevel.LOW, "read": RiskLevel.LOW, "screen": RiskLevel.LOW, "tmux": RiskLevel.LOW,
    "byobu": RiskLevel.LOW, "atq": RiskLevel.LOW, "script": RiskLevel.LOW, "scriptreplay": RiskLevel.LOW,
    "date": RiskLevel.LOW, "cal": RiskLevel.LOW, "bc": RiskLevel.LOW, "dc": RiskLevel.LOW,
    "seq": RiskLevel.LOW, "yes": RiskLevel.LOW, "sleep": RiskLevel.LOW, "expr": RiskLevel.LOW,
    "test": RiskLevel.LOW,
    "source": RiskLevel.MEDIUM, "exec": RiskLevel.MEDIUM, "eval": RiskLevel.MEDIUM,
    "crontab": RiskLevel.MEDIUM, "at": RiskLevel.MEDIUM, "atrm": RiskLevel.MEDIUM, "anacron": RiskLevel.MEDIUM,

    # Distribution-Specific Utilities
    "ubuntu-bug": RiskLevel.LOW, "apport-bug": RiskLevel.LOW, "lsb_release": RiskLevel.LOW,
    "sensible-editor": RiskLevel.LOW, "sensible-browser": RiskLevel.LOW, "sensible-pager": RiskLevel.LOW,
    "popularity-contest": RiskLevel.LOW,
    "do-release-upgrade": RiskLevel.HIGH, "ubuntu-drivers": RiskLevel.HIGH, "pro": RiskLevel.HIGH,
    "ubuntu-advantage": RiskLevel.HIGH, "canonical-livepatch": RiskLevel.HIGH,
    "update-manager": RiskLevel.HIGH, "update-locale": RiskLevel.HIGH
}


# ==============================================================================
# 2. EXHAUSTIVE WINDOWS (POWERSHELL & CMD) COMMAND RISK DATABASE
# ==============================================================================
WINDOWS_COMMANDS: Dict[str, RiskLevel] = {
    # Low Risk (Read-Only / Diagnostics / Information)
    "get-childitem": RiskLevel.LOW, "gci": RiskLevel.LOW, "dir": RiskLevel.LOW,
    "get-location": RiskLevel.LOW, "gl": RiskLevel.LOW, "pwd": RiskLevel.LOW,
    "get-content": RiskLevel.LOW, "gc": RiskLevel.LOW, "cat": RiskLevel.LOW, "type": RiskLevel.LOW,
    "get-command": RiskLevel.LOW, "gcm": RiskLevel.LOW,
    "get-help": RiskLevel.LOW, "help": RiskLevel.LOW, "man": RiskLevel.LOW,
    "get-process": RiskLevel.LOW, "gps": RiskLevel.LOW, "ps": RiskLevel.LOW,
    "get-service": RiskLevel.LOW, "gsv": RiskLevel.LOW,
    "get-item": RiskLevel.LOW, "gi": RiskLevel.LOW,
    "get-itemproperty": RiskLevel.LOW, "gp": RiskLevel.LOW,
    "test-path": RiskLevel.LOW,
    "measure-object": RiskLevel.LOW, "measure": RiskLevel.LOW,
    "select-string": RiskLevel.LOW, "sls": RiskLevel.LOW, "findstr": RiskLevel.LOW,
    "select-object": RiskLevel.LOW, "select": RiskLevel.LOW,
    "where-object": RiskLevel.LOW, "where": RiskLevel.LOW,
    "sort-object": RiskLevel.LOW, "sort": RiskLevel.LOW,
    "group-object": RiskLevel.LOW, "group": RiskLevel.LOW,
    "format-table": RiskLevel.LOW, "ft": RiskLevel.LOW,
    "format-list": RiskLevel.LOW, "fl": RiskLevel.LOW,
    "out-string": RiskLevel.LOW, "out-null": RiskLevel.LOW,
    "write-output": RiskLevel.LOW, "echo": RiskLevel.LOW, "write-host": RiskLevel.LOW,
    "get-date": RiskLevel.LOW,
    "get-netipaddress": RiskLevel.LOW, "ipconfig": RiskLevel.LOW,
    "get-netadapter": RiskLevel.LOW, "get-nettcpconnection": RiskLevel.LOW,
    "test-netconnection": RiskLevel.LOW, "tnc": RiskLevel.LOW, "ping": RiskLevel.LOW,
    "tracert": RiskLevel.LOW, "nslookup": RiskLevel.LOW, "pathping": RiskLevel.LOW,
    "systeminfo": RiskLevel.LOW, "hostname": RiskLevel.LOW, "whoami": RiskLevel.LOW,
    "get-volume": RiskLevel.LOW, "get-disk": RiskLevel.LOW, "get-partition": RiskLevel.LOW,
    "get-eventlog": RiskLevel.LOW, "get-winevent": RiskLevel.LOW,
    "get-localuser": RiskLevel.LOW, "get-localgroup": RiskLevel.LOW,
    "get-executionpolicy": RiskLevel.LOW,
    "fc": RiskLevel.LOW, "comp": RiskLevel.LOW,

    # Medium Risk (Local Mutations / Archiving / Temporary scripts)
    "new-item": RiskLevel.MEDIUM, "ni": RiskLevel.MEDIUM, "md": RiskLevel.MEDIUM, "mkdir": RiskLevel.MEDIUM,
    "copy-item": RiskLevel.MEDIUM, "cpi": RiskLevel.MEDIUM, "cp": RiskLevel.MEDIUM, "copy": RiskLevel.MEDIUM,
    "move-item": RiskLevel.MEDIUM, "mi": RiskLevel.MEDIUM, "mv": RiskLevel.MEDIUM, "move": RiskLevel.MEDIUM,
    "rename-item": RiskLevel.MEDIUM, "rni": RiskLevel.MEDIUM, "ren": RiskLevel.MEDIUM,
    "set-content": RiskLevel.MEDIUM, "sc": RiskLevel.MEDIUM,
    "add-content": RiskLevel.MEDIUM, "ac": RiskLevel.MEDIUM,
    "clear-content": RiskLevel.MEDIUM, "clc": RiskLevel.MEDIUM,
    "compress-archive": RiskLevel.MEDIUM, "expand-archive": RiskLevel.MEDIUM, "tar": RiskLevel.MEDIUM, "zip": RiskLevel.MEDIUM,
    "invoke-webrequest": RiskLevel.MEDIUM, "iwr": RiskLevel.MEDIUM, "curl": RiskLevel.MEDIUM, "wget": RiskLevel.MEDIUM,
    "invoke-restmethod": RiskLevel.MEDIUM, "irm": RiskLevel.MEDIUM,
    "start-process": RiskLevel.MEDIUM, "saps": RiskLevel.MEDIUM,
    "start-job": RiskLevel.MEDIUM, "stop-job": RiskLevel.MEDIUM,
    "export-csv": RiskLevel.MEDIUM, "export-clixml": RiskLevel.MEDIUM, "convertto-json": RiskLevel.MEDIUM,

    # High Risk (Administrative / Service Control / Kill / Registry / Firewall / Permissions)
    "remove-item": RiskLevel.HIGH, "ri": RiskLevel.HIGH, "rm": RiskLevel.HIGH, "del": RiskLevel.HIGH, "erase": RiskLevel.HIGH,
    "stop-process": RiskLevel.HIGH, "spps": RiskLevel.HIGH, "kill": RiskLevel.HIGH, "taskkill": RiskLevel.HIGH,
    "start-service": RiskLevel.HIGH, "stop-service": RiskLevel.HIGH, "restart-service": RiskLevel.HIGH, "net": RiskLevel.HIGH, "sc": RiskLevel.HIGH,
    "set-service": RiskLevel.HIGH, "new-service": RiskLevel.HIGH,
    "set-executionpolicy": RiskLevel.HIGH,
    "set-itemproperty": RiskLevel.HIGH, "sp": RiskLevel.HIGH, "new-itemproperty": RiskLevel.HIGH, "remove-itemproperty": RiskLevel.HIGH,
    "reg": RiskLevel.HIGH, "regini": RiskLevel.HIGH,
    "icacls": RiskLevel.HIGH, "cacls": RiskLevel.HIGH, "takeown": RiskLevel.HIGH,
    "new-localuser": RiskLevel.HIGH, "remove-localuser": RiskLevel.HIGH, "set-localuser": RiskLevel.HIGH,
    "add-localgroupmember": RiskLevel.HIGH, "remove-localgroupmember": RiskLevel.HIGH,
    "new-netfirewallrule": RiskLevel.HIGH, "set-netfirewallrule": RiskLevel.HIGH, "remove-netfirewallrule": RiskLevel.HIGH, "netsh": RiskLevel.HIGH,
    "stop-computer": RiskLevel.HIGH, "restart-computer": RiskLevel.HIGH, "shutdown": RiskLevel.HIGH,
    "install-package": RiskLevel.HIGH, "uninstall-package": RiskLevel.HIGH, "winget": RiskLevel.HIGH, "choco": RiskLevel.HIGH, "scoop": RiskLevel.HIGH,
    "wmic": RiskLevel.HIGH, "bcdedit": RiskLevel.HIGH, "sfc": RiskLevel.HIGH, "dism": RiskLevel.HIGH,

    # Critical Risk (Destructive / Disk Partitioning / Formatting / Disk Wipes)
    "format-volume": RiskLevel.CRITICAL, "format": RiskLevel.CRITICAL,
    "clear-disk": RiskLevel.CRITICAL, "initialize-disk": RiskLevel.CRITICAL,
    "remove-partition": RiskLevel.CRITICAL, "resize-partition": RiskLevel.CRITICAL,
    "diskpart": RiskLevel.CRITICAL, "cipher": RiskLevel.CRITICAL, "chkdsk": RiskLevel.CRITICAL
}


# ==============================================================================
# 3. EXHAUSTIVE MACOS (DARWIN / BSD) COMMAND RISK DATABASE
# ==============================================================================
MACOS_COMMANDS: Dict[str, RiskLevel] = {
    # Low Risk (Read-Only / Diagnostics / macOS Utilities)
    "sw_vers": RiskLevel.LOW, "system_profiler": RiskLevel.LOW, "scutil": RiskLevel.LOW,
    "defaults": RiskLevel.LOW, "csrutil": RiskLevel.LOW, "spctl": RiskLevel.LOW,
    "codesign": RiskLevel.LOW, "security": RiskLevel.LOW, "mdfind": RiskLevel.LOW,
    "mdls": RiskLevel.LOW, "pbcopy": RiskLevel.LOW, "pbpaste": RiskLevel.LOW,
    "plutil": RiskLevel.LOW, "otool": RiskLevel.LOW, "tmutil": RiskLevel.LOW,
    "pmset": RiskLevel.LOW, "ioreg": RiskLevel.LOW, "top": RiskLevel.LOW,
    "vm_stat": RiskLevel.LOW, "nettop": RiskLevel.LOW, "fs_usage": RiskLevel.LOW,
    "sc_usage": RiskLevel.LOW, "ls": RiskLevel.LOW, "cd": RiskLevel.LOW, "pwd": RiskLevel.LOW,
    "cat": RiskLevel.LOW, "grep": RiskLevel.LOW, "find": RiskLevel.LOW, "stat": RiskLevel.LOW,
    "df": RiskLevel.LOW, "du": RiskLevel.LOW, "ps": RiskLevel.LOW, "uname": RiskLevel.LOW,

    # Medium Risk (User Operations / GUI Automation / AppleScript / Archiving)
    "open": RiskLevel.MEDIUM, "osascript": RiskLevel.MEDIUM, "ditto": RiskLevel.MEDIUM,
    "hdiutil": RiskLevel.MEDIUM, "pkgutil": RiskLevel.MEDIUM, "brew": RiskLevel.MEDIUM,
    "mkdir": RiskLevel.MEDIUM, "cp": RiskLevel.MEDIUM, "mv": RiskLevel.MEDIUM, "touch": RiskLevel.MEDIUM,
    "tar": RiskLevel.MEDIUM, "zip": RiskLevel.MEDIUM, "unzip": RiskLevel.MEDIUM, "rsync": RiskLevel.MEDIUM,

    # High Risk (Administrative / Daemons / Firewall / User Directory Management)
    "launchctl": RiskLevel.HIGH, "networksetup": RiskLevel.HIGH, "dscl": RiskLevel.HIGH,
    "softwareupdate": RiskLevel.HIGH, "sudo": RiskLevel.HIGH, "su": RiskLevel.HIGH,
    "chmod": RiskLevel.HIGH, "chown": RiskLevel.HIGH, "chflags": RiskLevel.HIGH,
    "kill": RiskLevel.HIGH, "pkill": RiskLevel.HIGH, "killall": RiskLevel.HIGH,
    "pfctl": RiskLevel.HIGH, "nvram": RiskLevel.HIGH, "kextload": RiskLevel.HIGH,
    "kextunload": RiskLevel.HIGH, "kmutil": RiskLevel.HIGH, "dtrace": RiskLevel.HIGH,
    "rm": RiskLevel.HIGH,

    # Critical Risk (Disk Formatting / APFS Destruction / Low-Level Wipes)
    "diskutil": RiskLevel.CRITICAL, "gpt": RiskLevel.CRITICAL, "newfs_apfs": RiskLevel.CRITICAL,
    "newfs_hfs": RiskLevel.CRITICAL, "dd": RiskLevel.CRITICAL, "asr": RiskLevel.CRITICAL
}


# Dangerous anti-patterns that must always be evaluated as CRITICAL on any platform
GLOBAL_DANGEROUS_PATTERNS = [
    r"rm\s+-(?:r|f|rf|fr)\s+/(?:\s|$|\*)",
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:",
    r"dd\s+if=/dev/zero",
    r"dd\s+if=/dev/urandom",
    r"mkfs\.[a-z0-9]+\s+/dev/sd[a-z]",
    r">\s*/dev/sd[a-z]",
    r"chmod\s+-(?:R|r)\s+777\s+/",
    r"chown\s+-(?:R|r)\s+nobody\s+/",
    r"mv\s+/\s+/dev/null",
    r"wget.*\|\s*(?:sh|bash)",
    r"curl.*\|\s*(?:sh|bash)",
    r"format-volume\s+-driveletter",
    r"clear-disk\s+-number",
    r"diskpart\s+/s",
    r"diskutil\s+eraseDisk"
]


from dataclasses import dataclass, field


@dataclass
class CommandRiskEvaluation:
    level: RiskLevel
    requires_approval: bool
    recommended_action: str
    reasons: List[str] = field(default_factory=list)


class CommandRiskClassifier:
    """Classifies terminal commands into risk tiers across Linux, Windows, and macOS."""

    @classmethod
    def get_database_for_os(cls, os_type: str) -> Dict[str, RiskLevel]:
        if os_type == "windows":
            return WINDOWS_COMMANDS
        elif os_type == "macos":
            return MACOS_COMMANDS
        else:
            return LINUX_COMMANDS

    @classmethod
    def classify_command(cls, raw_command: str, os_type: str = None, strict_mode: bool = False) -> Tuple[RiskLevel, bool, str]:
        """
        Evaluates a raw shell command line against the OS risk matrix.
        In strict mode, critical destructive patterns and dangerous path access are blocked immediately without prompting.
        Returns: (RiskLevel, requires_approval, reasoning)
        """
        from src.core.security_policy import SecurityPolicyManager

        if os_type is None:
            os_type = OSDetector.get_os_type()

        stripped = raw_command.strip()
        if not stripped:
            return RiskLevel.LOW, False, "Empty command"

        # 1. Check global and OS-specific destructive anti-patterns
        all_patterns = list(GLOBAL_DANGEROUS_PATTERNS) + SecurityPolicyManager.get_critical_denied_patterns_for_os(os_type)
        for pattern in all_patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                if strict_mode:
                    return (
                        RiskLevel.CRITICAL,
                        False,
                        f"[STRICT BLOCKED] Command matches critical destructive anti-pattern: {pattern}. Blocked immediately without prompting."
                    )
                else:
                    return (
                        RiskLevel.CRITICAL,
                        True,
                        f"Command matches critical destructive anti-pattern: {pattern}. Requires explicit multi-step confirmation."
                    )

        # 2. Check for dangerous OS paths within command arguments
        tokens = stripped.split()
        for token in tokens[1:]:
            clean_token = token.strip("'\"`=,;")
            if clean_token and SecurityPolicyManager.is_dangerous_path(clean_token, os_type):
                if strict_mode:
                    return (
                        RiskLevel.CRITICAL,
                        False,
                        f"[STRICT BLOCKED] Command accesses dangerous OS path '{clean_token}'. Blocked immediately without prompting."
                    )
                else:
                    return (
                        RiskLevel.HIGH,
                        True,
                        f"Command accesses sensitive OS path '{clean_token}'. Requires explicit user confirmation before accessing."
                    )

        # 3. Extract base command
        cmd = tokens[0].lower()

        # Handle execution wrappers (sudo, doas, powershell -command, etc.)
        wrappers = {"sudo", "doas", "nohup", "time", "timeout", "xargs", "env", "powershell", "pwsh", "cmd", "bash", "sh"}
        idx = 0
        while idx < len(tokens) and tokens[idx].lower().strip("-/\\") in wrappers:
            idx += 1

        if idx < len(tokens):
            cmd = Path(tokens[idx].lower()).name

        db = cls.get_database_for_os(os_type)
        risk = db.get(cmd)

        # If not found in current OS database, check other DBs as fallback
        if risk is None:
            for fallback_db in (LINUX_COMMANDS, WINDOWS_COMMANDS, MACOS_COMMANDS):
                if cmd in fallback_db:
                    risk = fallback_db[cmd]
                    break

        if risk is None:
            # Default unknown command to MEDIUM risk to guarantee human safety
            risk = RiskLevel.MEDIUM

        # Policy evaluation:
        if risk == RiskLevel.CRITICAL and strict_mode:
            requires_approval = False
            reasoning = f"[STRICT BLOCKED] [{os_type.upper()}] Command '{cmd}' is classified as CRITICAL. Blocked immediately without prompting."
        elif risk != RiskLevel.LOW:
            requires_approval = True
            reasoning = f"[{os_type.upper()}] Command '{cmd}' is classified as {risk.value} risk. Requires user approval before execution."
        else:
            requires_approval = False
            reasoning = f"[{os_type.upper()}] Command '{cmd}' is classified as LOW risk. Permitted for automatic execution."

        return risk, requires_approval, reasoning

    def classify(self, raw_command: str, os_type: str = None, strict_mode: bool = False) -> CommandRiskEvaluation:
        """Evaluates command line and returns structured CommandRiskEvaluation object."""
        risk, req_approval, reason = self.classify_command(raw_command, os_type=os_type, strict_mode=strict_mode)
        if "[STRICT BLOCKED]" in reason:
            action = "blocked immediately (zero-trust)"
        elif req_approval:
            action = "prompt user for approval"
        else:
            action = "auto-execute permitted"

        return CommandRiskEvaluation(
            level=risk,
            requires_approval=req_approval,
            recommended_action=action,
            reasons=[reason] if reason else []
        )

