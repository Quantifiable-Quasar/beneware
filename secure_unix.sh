

# CIS 1.1.1 Disable Unused File Systems

filesystems="cramfs freevxfs jffs2 hfs hfsplus udf"

for i in $filesystems;
do
        echo install $i /bin/true >> /etc/modprobe.d/$i.conf
        rnmod $i
done

# CIS 1.1.2 Ensure /tmp is configured

echo "tmpfs     /tmp    tmpfs   defaults,rw,nosuid,nodev,noexec,realtime 0 0" >> /etc/fstab

findmnt -n /tmp | grep -v nodev
findmnt -n /tmp | grep -v nosuid
findmnt -n /tmp | grep -v noexec


# CIS 1.1.6 Ensure /dev/shm is configured

echo "tmpfs     /dev/shm    tmpfs   defaults,noexec,nodev,nosuid,seclabel   0 0" >> /etc/fstab
mount -o remount,noexec,nodev,nosuid /dev/shm

findmnt -n /dev/shm | grep -v nodev
findmnt -n /dev/shm | grep -v nosuid
findmnt -n /dev/shm | grep -v noexec

# CIS 1.1.10 - 1.1.21 are ignored
# The partitions make me nervous

# CIS 1.1.22 Ensure sticky bit is set on all world-writable dirs
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'

# CIS 1.1.23 Disable automounting
systemctl --now disable autofs
apt purge autofs

# CIS 1.1.24 Disable USB sorage
echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb_storage.conf
rnmod usb-storate

# CIS 1.3.1 Ensure AIDE is installed
# todo

# CIS 1.4.1 Ensure permissions on bootloader config are not overwritten
#sed -ri 's/chmod\s+[0-7][0-7][0-7]\s+\$\{grub cfg\}\.new/chmod 400 ${grub_cfg}.new/' /usr/sbin/grub-mkconfig
# nervous
# todo

# CIS 1.5.1 Ensure XD/NX support is enabled
journalctl | grep 'NX (Execute'

# CIS 1.5.2 Ensure ASLR is enabled
sysctl kernel.randomize va space
grep -Es "^\s*kernel\.randomize va space\s*=\s*([0-1]|[3-9]|[1-9][0-9]+)" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib.sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /run/sysctl.d/*.conf

# CIS 1.5.3 Ensure prelink is disabled
prelink -ua 2>/dev/null
apt purge prelink

# CIS 1.5.4 Ensure core dumps are restriced
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

coredumps=$(sysctl is-enabled coredump.service 2>/dev/null 2>/dev/null)
if [[ $coredumps -ne "" ]];
then
        echo "Storage=none" >> /etc/systemd/coredump.conf
        echo "ProcessSizeMax=0" >> /etc/systemd/coredump.conf
        systemctl daemon-reload
fi

# CIS 1.6 requires OS info skipping for now
# todo 

# CIS 1.8.4 Ensure XDCMP is not enabled
xdcmp=$(grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf)
if [[ $xdcmp -ne "" ]];
then
        echo Disable XDCMP
        echo $xdcmp
fi

# CIS 2.1.3 Ensure Avahi Server is not installed
systemctl stop avahi-daemon.service
systemctl stop avahi-daemon.socket

# CIS 2.1.3 - 2.1.14, 2.1.16 - 2.2.6 Ensure a bunch of stuff is not installed
to_purge="avahi-daemon cups isc-dhcp-server slapd nfs-kernel-server vsftpd samba squid snmpd rsync nis rsh-client talk telnet ldap-utils rpcbind"
apt purge $to_purge -y

# CIS 2.1.15 Ensure mail transfer agent is configured for local-only mode
# Except for mail servers

mta=$(ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s')
if [[ $mta -ne "" ]];
then
        echo Is this mail server???
        echo $mta
fi

# CIS 3.1.1 Disable IPv6
# Maybe?
# todo

echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.route.flush=1

# CIS 3.2.1 Ensure packet redirect sending is disabled
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

# CIS 3.2.2 Ensure IP forwarding is disabled
# todo

echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_soute=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1

# CIS 3.3.2 Ensure ICMP rdirects are not accepted
# I think we want pings
# todo

# CIS 3.3.3 Ensure secure ICMP redirects are not accepted
# ping 
# todo

# CIS 3.3.4 Ensure suspicous packets are logged

echo "net.ipv4.conf.all.log martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

# CIS 3.3.5 Ensure broadcast ICMP requests are ignored
# I think we can ignore these ones

echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

# CIS 3.3.6 Ensure bogus ICMP responses are ignored

echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1

# CIS 3.3.7 Ensure Reverse Path Filtering is enabled

echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

# CIS 3.3.8 Ensure TCP SYN cookies is enabled

echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

# CIS 3.3.9 Ensure IPv6 router advertisements are not accepted
# this doesn't matter if ipv6 is disabled
# todo

# CIS 3.4.1 - 3.4.4 Ensure uncommon protocols are disabled
protocols="dccp sctp rds tipc"

for i in $protocols;
do 
        echo "install $i /bin/true" >> /etc/modprobe.d/$i.conf
done

# CIS 4.1.1.1 Ensure auditd is installed

apt intsll auditd audispd-plugins -y

# CIS 4.1.1.2 Ensure auditd service is enabled

systemctl --now enable auditd

# CIS 4.1.3 Ensure events that modify date and time informatino are collected

echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/50-time-change.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/50-time-change.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/50-time-change.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/50-time-change.rules
echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/50-time-change.rules

# CIS 4.1.4 Ensure events that modify user/group information are collected

echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules

# CIS 4.1.5 Ensure events that modify the system's network environment are collected

echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules
echo "-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules

# CIS 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected
# this monitors apparmor 
# wil not implement yet
# todo

# CIS 4.1.7 Ensure login and logout events are collected

echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/50-logins.rules
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/50-logins.rules
echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/50-logins.rules

# CIS 4.1.8 Ensure session initiation informatino is collected

echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/50-session.rules
echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/50-session.rules
echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/50-session.rules

# CIS 4.1.9 Ensure discretionary access control permission modificatino events are collected

echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4284867285 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S chownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S chownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules

# CIS 4.1.10 Ensure Unsucessful unauthorized file access attempts are collected

echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/50-access.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/50-access.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/50-access.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=4294967295 -k access"  >> /etc/audit/rules.d/50-access.rules

# CIS 4.1.11 Ensure use of privileged commands in collected
# ignored
# todo

# CIS 4.1.12 Ensure successful file system mounts are collected

echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4284867285 -k mounts" >> /etc/audit/rules.d/50-mounts.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4284867285 -k mounts" >> /etc/audit/rules.d/50-mounts.rules

# CIS 4.1.13 Ensure file deletion events by users are collected
# ignored
# todo

# CIS 4.1.14 Ensure changes to system administratino scope (sudoers) is collected

echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/50-scope.rules
echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/50-scope.rules

# CIS 4.1.15 Ensure system administrator command executions are collected
# ignored
# todo

# CIS 4.1.16 Ensure kernel module loading and unloading is collected 

echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/50-modules.rules
echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/50-modules.rules
echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/50-modules.rules
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/50-modules.rules

# CIS 4.1.17 Ensure the audit configuration is immutable

echo "-e 2" >> /etc/audit/rules.d/99-finalize.rules

systemctl restart auditd

# CIS 5.1.1 Ensure cron daemon is enabled and running

systemctl --now enable cron

# CIS 5.1.2 Ensure permissions on /etc/crontab are configured

chown root:root /etc/crontab
chmod og-rwx /etc/crontab

# CIS 5.1.3 Ensure permissions on /etc/cron.hourly are configured

chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/

# CIS 5.1.4 Ensure permissions on /etc/cron.daily are configured

chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/

# CIS 5.1.5 Ensure permissions on /etc/cron.weekly are configured

chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/

# CIS 5.1.6 Ensure permissions on /etc/cron.monthly are configured

chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

# CIS 5.1.7 Ensure permissions on /etc/cron.d are configured

chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

# CIS 5.2.1 Ensure sudo is installed

apt install sudo

# CIS 5.2.2 Ensure sudo commands use pty

echo "Defaults use_pty" | EDITOR="tee -a" visudo

# CIS 5.2.3 Ensure sudo log file exists

echo "Defaults logfile ='/var/log/sudo.log'" | EDITOR="tee -a" visudo

# skipping ssh
# todo

# skipping pam

# CIS 5.5.3 Ensure default group for the foor account is GID 0
 
usermod -g 0 root

# CIS 5.5.5 Ensure default user shell timeout is 900 seconds or less
# annoying
# todo

:'
echo "TMOUT=900" >> /etc/profile
echo "readonly TMOUT" >> /etc/profile
echo "export TMOUT" >> /etc/profile
'

# CIS 5.6 Ensure root login is restricted to system consold

cat /etc/securetty

# CIS 5.7 Ensure access to the su command is restricted
# todo
#groupadd sugroup
#echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su

# CIS 6.1.2 Ensure permissions on /etc/passwd are configured

chown root:root /etc/passwd
chmod u-x,go-wx /etc/passwd

# CIS 6.1.3 Ensure permissions on /etc/passwd- are configured

chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-

# CIS 6.1.4 Ensure permissions on /etc/group are configured

chown root:root /etc/group
chmod u-x,go-wx /etc/group

# CIS 6.1.5 Ensure permission on /etc/group- are configured

chown root:root /etc/group-
chmod u-x,go-wx /etc/group-

# CIS 6.1.6 Ensure permissions on /etc/shadow are configured

chown root:root /etc/shadow
chmod u-x,g-wx,o-rwx /etc/shadow

# CIS 6.1.7 Ensure permissions on /etc/shadow- are configured

chown root:root /etc/shadow-
chmod u-x,g-wx,o-rwx /etc/shadow-

# CIS 6.1.8 Ensure permissions on /etc/gshadow are configured

chown root:root /etc/gshadow
chmod u-x,g-wx,o-rwx /etc/gshadow

# CIS 6.1.9 Ensure permission on /etc/gshadow- are confgiured

chown root:root /etc/gshadow-
chmod u-x,g-wx,o-rwx /etc/gshadow-

# CIS 6.1.10 Ensure no world writable files exist

find / -xdev -type f -perm -0002

# CIS 6.1.11 Ensure no unowned files or directories exist

find / -xdev -nouser

# CIS 6.1.12 Ensure no ungrouped files or directories exist

find / -xdev -nogroup

# CIS 6.1.13 Audit SUID executables

find / -xdev -type f -perm -4000

# CIS 6.1.14 Audit SGID executables

find / -xdev -type f -perm -2000

# CIS 6.2.1 Ensure accounts in /etc/passwd use shadowed passwords

awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}' /etc/passwd

# CIS 6.2.2 Ensure password fileds are not empty

awk -F: '($2 == "") { print $1 " does not have a password " }' /etc/shadow

# CIS 6.2.3 Ensure all groups in /etc/passwd exist in /etc/group

for i in $(cut -s -d: -f4 /etc/passwd | sort -u); do
        grep -q -P "^.*?:[^:]*:$i:" /etc/group
        if [ $? -ne 0 ]; then
                echo "Group $i is is refrenced by /etc/passwd by does not exist in /etc/group"
        fi
done

# CIS 6.2.7 Ensure users' dot files are not group or world writable

awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/
&& $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while
read -r user dir; do
    if [ -d "$dir" ]; then
        for file in "$dir"/.*; do
            if [ ! -h "$file" ] && [ -f "$file" ]; then
                fileperm=$(stat -L -c "%A" "$file")
                if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then
        echo "User: \"$user\" file: \"$file\" has permissions:\"$fileperm\""
                fi
            fi
        done
    fi
done

# CIS 6.2.8 Ensure no users have .netrc files
# 600 is the perms we want

awk -F: '($1!~/(halt|sync|shutdown)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/
&& $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while
read -r user dir; do
    if [ -d "$dir" ]; then
            file="$dir/.netrc"
            if [ ! -h "$file" ] && [ -f "$file" ]; then
                    if stat -L -c "%A" "$file" | cut -c4-10 | grep -Eq '[^-]+'; then
                            echo "FAILED: User: \"$user\" file: \"$file\" exists with permissions: \"$(stat -L -c "%a" "$file")\", remove file or excessive permissions"
                    else
                            echo "WARNING: User: \"$user\" file: \"$file\" exists with permissions: \"$(stat -L -c "%a" "$file")\", remove file unless required"
                    fi
            fi
    fi
done

# CIS 6.2.11 Ensure root is the only UID 0 account

if [[ $(awk -F: '($3 == 0) { print $i }' /etc/passwd) -ne "root" ]]
then
        awk -F: '($3 == 0) { print $i }' /etc/passwd
fi

# CIS 6.2.12 Ensure root PATH integrity

RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
echo "$RPCV" | grep -q "::" && echo "root's path contains an empty dir (::)"
echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
for x in $(echo "$RPCV" | tr ":" " "); do
        if [ -d "$x" ]; then
                ls -ldH "$x" | awk '-9 == "." {print "PATH contains working dir (.)"} $3 != "root" {print $9, "is not owned by root"} substr($1,6,1) != "-" {print $9, "is group writable"} substr($1,9,1) != "-" {print $9, "is world writable"}'
        else
                echo "$x is not a directory"
        fi
done

# CIS 6.2.13 Ensure no duplicate UIDs exist

cut -f3 -d":" /etc/passwd | sort -n | uniq -c while read x; 
do 
        [ -z "$x" ] && break
        set - $x
        if [[ $1 -gt 1 ]]; then
                users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
                echo "Duplicate UID ($2): $users"
        fi
done

# CIS 6.2.14 Ensure no duplicate GIDs exist

cud -d":" -f3 /etc/group | sort | uniq -d | while read x; do
    echo "Duplicate GID ($x) in /etc/group"
done

# CIS 6.2.15 Ensure no duplicate user names exist

cut -d ":" -f 1 /etc/passwd | sort | uniq | uniq -d | while read -r x; do
    echo "Duplicate login name $x in /etc/passwd"
done

# CIS 6.2.16 Ensure no duplicate group names exist

cut -d ":" -f 1 /etc/group | sort | uniq -d | while read -r x; do
    echo "Duplicate group name $x in /etc/group"
done

# CIS 6.2.17 Ensure shadow group is empty

grep ^shadow:[^:]*:[^:]*[^:]+ /etc/group
awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" ' ($4==GID) {print}' /etc/passwd

