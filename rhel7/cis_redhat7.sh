#!/bin/bash -
#CIS Security Audit Script
#Author: Vijay Anand
#It will dump the report to /root/report.txt for review.


echo "*********************************************************"
echo "CIS Security Audit Script"
echo "Red Hat 7"
echo "Output can be found in /root/report.txt"
echo "*********************************************************"

exec > >(tee "/root/report.txt") 2>&1

echo "CIS Security Audit Report"
echo "*DATE*"
date
echo "*OS*"
/etc/redhat-release
echo "*KERNEL*"
uname -a 
echo "*HOST*"
hostname
echo "*********************************************************"
echo "******1.1.1 Disable Unused File Systems******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "1.1.1.1 Ensure mounting of cramfs filesystems is disabled"
echo "*********************************************************"
echo ""
echo "$ modprobe -n -v cramfs"
modprobe -n -v cramfs
echo "$ lsmod | grep -c cramfs"
lsmod | grep -c cramfs

echo "*********************************************************"
echo "1.1.1.2 Ensure mounting of freevxfs filesystems is disabled"
echo "*********************************************************"
echo ""
echo "$ modprobe -n -v freevxfs"
modprobe -n -v freevxfs
echo "$ lsmod | grep -c freevxfs"
lsmod | grep -c freevxfs

echo "*********************************************************"
echo "1.1.1.3 Ensure mounting of jffs2 filesystems is disabled"
echo "*********************************************************"
echo ""
echo "$ modprobe -n -v jffs2"
modprobe -n -v jffs2
echo "$ lsmod | grep -c jffs2"
lsmod | grep -c jffs2

echo "*********************************************************"
echo "1.1.1.4 Ensure mounting of hfs filesystems is disabled"
echo "*********************************************************"
echo ""
echo "$ modprobe -n -v hfs"
modprobe -n -v hfs
echo "$ lsmod | grep -c hfs"
lsmod | grep -c hfs

echo "*********************************************************"
echo "1.1.1.5 Ensure mounting of hfsplus filesystems is disabled"
echo "*********************************************************"
echo ""
echo "$ modprobe -n -v hfsplus"
modprobe -n -v hfsplus
echo "$ lsmod | grep -c hfsplus"
lsmod | grep -c hfsplus

echo "*********************************************************"
echo "1.1.1.6 Ensure mounting of squashfs filesystems is disabled"
echo "*********************************************************"
echo ""
echo "$ modprobe -n -v squashfs"
modprobe -n -v squashfs
echo "$ lsmod | grep -c squashfs"
lsmod | grep -c squashfs

echo "*********************************************************"
echo "1.1.1.7 Ensure mounting of udf filesystems is disabled"
echo "*********************************************************"
echo ""
echo "$ modprobe -n -v udf"
modprobe -n -v udf
echo "$ lsmod | grep -c udf"
lsmod | grep -c udf

echo "*********************************************************"
echo "1.1.1.8 Ensure mounting of FAT filesystems is disabled"
echo "*********************************************************"
echo ""
echo "$ modprobe -n -v vfat"
modprobe -n -v vfat
echo "$ lsmod | grep -c vfat"
lsmod | grep -c vfat

echo "*********************************************************"
echo "1.1.2 Ensure separate partition exists for /tmp"
echo "*********************************************************"
echo ""
mount | grep /tmp

echo "*********************************************************"
echo "For 1.1.3 , 1.1.4 , 1.1.5:"
echo "Check nodev,nosuid,noexec are set on /tmp"
echo "By verifying from the output of 1.1.2"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "1.1.6 Ensure separate partition exists for /var"
echo "*********************************************************"
echo ""
mount | grep /var

echo "*********************************************************"
echo "1.1.7 Ensure separate partition exists for /var/tmp"
echo "*********************************************************"
echo ""
mount | grep /var/tmp

echo "*********************************************************"
echo "For 1.1.8 , 1.1.9 , 1.1.10:"
echo "Check nodev,nosuid,noexec are set on /var/tmp"
echo "By verifying from the output of 1.1.7"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "1.1.11 Ensure separate partition exists for /var/log"
echo "*********************************************************"
echo ""
mount | grep /var/log

echo "*********************************************************"
echo "1.1.12 Ensure separate partition exists for /var/log/audit"
echo "*********************************************************"
echo ""
mount | grep /var/log/audit

echo "*********************************************************"
echo "1.1.13 Ensure separate partition exists for /home"
echo "*********************************************************"
echo ""
mount | grep /home

echo "*********************************************************"
echo "For 1.1.14:"
echo "Check nodev is set on /home"
echo "By verifying from the output of 1.1.13"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "For 1.1.15 , 1.1.16 , 1.1.17:"
echo "Check nodev,nosuid,noexec are set on /dev/shm"
echo "*********************************************************"
echo ""
mount | grep /dev/shm

echo "*********************************************************"
echo "1.1.18 Ensure nodev option set on removable media partitions"
echo "*********************************************************"
echo ""
mount

echo "*********************************************************"
echo "1.1.19 Ensure nosuid option set on removable media partitions"
echo "*********************************************************"
echo ""
mount

echo "*********************************************************"
echo "1.1.20 Ensure noexec option set on removable media partitions"
echo "*********************************************************"
echo ""
mount

echo "*********************************************************"
echo "1.1.21 Ensure sticky bit is set on all world-writable directories"
echo "*********************************************************"
echo ""
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null

echo "*********************************************************"
echo "1.1.22 Disable Automounting"
echo "*********************************************************"
echo ""
systemctl is-enabled autofs

echo "*********************************************************"
echo "******1.2 Configure Software Updates******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "1.2.1 Ensure package manager repositories are configured"
echo "*********************************************************"
echo ""
yum repolist

echo "*********************************************************"
echo "1.2.2 Ensure gpgcheck is globally activated"
echo "*********************************************************"
echo ""
grep ^gpgcheck /etc/yum.conf

echo "*********************************************************"
echo "1.2.3 Ensure GPG keys are configured"
echo "*********************************************************"
echo ""
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'

echo "*********************************************************"
echo "1.2.4 Ensure Red Hat Network or Subscription Manager connection is configured"
echo "*********************************************************"
echo ""
subscription-manager identity

echo "*********************************************************"
echo "1.2.5 Disable the rhnsd Daemon"
echo "*********************************************************"
echo ""
chkconfig --list rhnsd

echo "*********************************************************"
echo "******1.3 Filesystem Integrity Checking******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "1.3.1 Check if AIDE is installed"
echo "*********************************************************"
echo ""
rpm -q aide

echo "*********************************************************"
echo "1.3.2 Check if filesystem is regularly checked"
echo "*********************************************************"
echo ""

echo "$ crontab -u root -l | grep aide"
crontab -u root -l | grep aide

echo "$ grep -r aide /etc/cron.* /etc/crontab"
grep -r aide /etc/cron.* /etc/crontab

echo "*********************************************************"
echo "******1.4 Secure Boot Settings******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "1.4.1 Ensure permissions on bootloader config are configured"
echo "*********************************************************"
echo ""

echo "$ stat /boot/grub2/grub.cfg"
stat /boot/grub2/grub.cfg

echo "$ stat /boot/grub2/user.cfg"
stat /boot/grub2/user.cfg


echo "*********************************************************"
echo "1.4.2 Ensure bootloader password is set"
echo "*********************************************************"
echo ""

echo "grep "^GRUB2_PASSWORD" /boot/grub2/grub.cfg"
grep "^GRUB2_PASSWORD" /boot/grub2/grub.cfg

echo "$ grep '"^set superusers"' /boot/grub2/grub.cfg"
grep "^set superusers" /boot/grub2/grub.cfg

echo "$ grep '"^password"' /boot/grub2/grub.cfg"
grep "^password" /boot/grub2/grub.cfg

echo "*********************************************************"
echo "1.4.3 Check if authentication is required for single user mode"
echo "*********************************************************"
echo ""

echo "$ grep /sbin/sulogin /usr/lib/systemd/system/rescue.service"
grep /sbin/sulogin /usr/lib/systemd/system/rescue.service

echo "$ grep /sbin/sulogin /usr/lib/systemd/system/emergency.service"
grep /sbin/sulogin /usr/lib/systemd/system/emergency.service

echo "*********************************************************"
echo "******1.5 Additional Process Hardening******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "1.5.1 Ensure core dumps are restricted"
echo "*********************************************************"
echo ""

echo '"$ grep '"hard core"' /etc/security/limits.conf /etc/security/limits.d/*"'
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*

echo "$ sysctl fs.suid_dumpable"
sysctl fs.suid_dumpable

echo '"$ fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*'
grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*

echo "*********************************************************"
echo "1.5.2 Check if XD/NX support is enabled"
echo "*********************************************************"
echo ""
dmesg | grep NX

echo "*********************************************************"
echo "1.5.3 Ensure address space layout randomization (ASLR) is enabled"
echo "*********************************************************"
echo ""
sysctl kernel.randomize_va_space

echo "*********************************************************"
echo "1.5.4 Ensure prelink is disabled"
echo "*********************************************************"
echo ""
rpm -q prelink

echo "*********************************************************"
echo "******1.6 Mandatory Access Controls******"
echo "*********************************************************"

echo "*********************************************************"
echo "1.6.1.1 Ensure SELinux is not disabled in bootloader configuration"
echo "*********************************************************"
echo ""
grep "^\s*linux" /boot/grub2/grub.cfg

echo "*********************************************************"
echo "1.6.1.2 Ensure the SELinux state is enforcing"
echo "*********************************************************"
echo ""

echo "$ grep SELINUX=enforcing /etc/selinux/config"
grep SELINUX=enforcing /etc/selinux/config

echo "$ sestatus"
sestatus

echo "*********************************************************"
echo "1.6.1.3 Ensure SELinux policy is configured"
echo "*********************************************************"
echo ""

echo "$ grep SELINUXTYPE=targeted /etc/selinux/config"
grep SELINUXTYPE=targeted /etc/selinux/config

echo "$ sestatus"
sestatus

echo "*********************************************************"
echo "1.6.1.4 Ensure SETroubleshoot is not installed"
echo "*********************************************************"
echo ""
rpm -q setroubleshoot

echo "*********************************************************"
echo "1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed"
echo "*********************************************************"
echo ""
rpm -q mcstrans

echo "*********************************************************"
echo "1.6.1.6 Ensure no unconfined daemons exist"
echo "*********************************************************"
echo ""
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'

echo "*********************************************************"
echo "1.6.2 Check if SELinux is installed"
echo "*********************************************************"
echo ""
rpm -q libselinux

echo "*********************************************************"
echo "******1.7 Warning Banners******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "1.7.1.1 Ensure message of the day is configured properly"
echo "*********************************************************"
echo ""

echo "run this command and verify that the contents match site policy"
cat /etc/motd

echo "Run the following command and verify no results are returned"
egrep '(\\v|\\r|\\m|\\s)' /etc/motd

echo "*********************************************************"
echo "1.7.1.2 Ensure local login warning banner is configured properly"
echo "*********************************************************"
echo ""

echo "Run the following command and verify that the contents match site policy"
cat /etc/issue

echo "Run the following command and verify no results are returned"
egrep '(\\v|\\r|\\m|\\s)' /etc/issue

echo "*********************************************************"
echo "1.7.1.3 Ensure remote login warning banner is configured properly"
echo "*********************************************************"
echo ""

echo "Run the following command and verify that the contents match site policy"
cat /etc/issue.net

echo "Run the following command and verify no results are returned"
egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net

echo "*********************************************************"
echo "1.7.1.4 Ensure permissions on /etc/motd are configured"
echo "*********************************************************"
echo ""
stat /etc/motd

echo "*********************************************************"
echo "1.7.1.5 Ensure permissions on /etc/issue are configured"
echo "*********************************************************"
echo ""
stat /etc/issue

echo "*********************************************************"
echo "1.7.1.6 Ensure permissions on /etc/issue.net are configured"
echo "*********************************************************"
echo ""
stat /etc/issue.net

echo "*********************************************************"
echo "******1.8 Ensure updates, patches and additional security software are installed******"
echo "*********************************************************"
echo ""
yum check-update --security

echo "*********************************************************"
echo "******2 Services******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "For 2.1.1 to 2.1.6 check:"
echo "2.1.1 : chargen-dgram and chargen-stream are off or missing"
echo "2.1.2 : daytime-dgram and daytime-stream are off or missing"
echo "2.1.3 : discard-dgram and discard-stream are off or missing"
echo "2.1.4 : echo-dgram and echo-stream are off or missing"
echo "2.1.5 : time-dgram and time-stream are off or missing"
echo "2.1.6 : tftp is off or missing"
echo "*********************************************************"
echo ""
chkconfig --list

echo "*********************************************************"
echo "2.1.7 Ensure xinetd is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled xinetd

echo "*********************************************************"
echo "******2.2 Special Purpose Services******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "2.2.1 Time Synchronization"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "2.2.1.1 Check if time synchronization is in use"
echo "*********************************************************"
echo ""

echo "$ rpm -q ntp"
rpm -q ntp

echo "$ rpm -q chrony"
rpm -q chrony

echo "*********************************************************"
echo "2.2.1.2 Check if ntp is properly configured"
echo "*********************************************************"
echo ""

echo '"$ grep '"^restrict"' /etc/ntp.conf"'
grep "^restrict" /etc/ntp.conf

echo '$ grep "^server" /etc/ntp.conf'
grep "^server" /etc/ntp.conf

echo '"$ grep '"^OPTIONS"' /etc/sysconfig/ntpd"'
grep "^OPTIONS" /etc/sysconfig/ntpd

echo '"$ grep '"^ExecStart"' /usr/lib/systemd/system/ntpd.service"'
grep "^ExecStart" /usr/lib/systemd/system/ntpd.service

echo "*********************************************************"
echo "2.2.1.3 Ensure chrony is configured"
echo "*********************************************************"
echo ""

echo '"$ grep ^server /etc/chrony.conf"'
grep "^server" /etc/chrony.conf

echo "$ grep ^OPTIONS /etc/sysconfig/chronyd"
grep ^OPTIONS /etc/sysconfig/chronyd

echo "*********************************************************"
echo "2.2.2 Ensure X Window System is not installed"
echo "*********************************************************"
echo ""
rpm -qa xorg-x11*

echo "*********************************************************"
echo "2.2.3 Ensure AVAHI server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled avahi-daemon

echo "*********************************************************"
echo "2.2.4 Ensure CUPS is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled cups

echo "*********************************************************"
echo "2.2.5 Ensure DHCP server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled dhcpd

echo "*********************************************************"
echo "2.2.6 Ensure LDAP server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled slapd

echo "*********************************************************"
echo "2.2.7 Ensure NFS and RPC are not enabled"
echo "*********************************************************"
echo ""

echo "$ systemctl is-enabled nfs"
systemctl is-enabled nfs

echo "$ systemctl is-enabled nfs-server"
systemctl is-enabled nfs-server

echo "$ systemctl is-enabled rpcbind"
systemctl is-enabled rpcbind

echo "*********************************************************"
echo "2.2.8 Ensure DNS server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled named

echo "*********************************************************"
echo "2.2.9 Ensure FTP server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled vsftpd

echo "*********************************************************"
echo "2.2.10 Ensure HTTP server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled httpd

echo "*********************************************************"
echo "2.2.11 Ensure IMAP and POP3 server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled dovecot

echo "*********************************************************"
echo "2.2.12 Ensure SAMBA server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled smb

echo "*********************************************************"
echo "2.2.13 Ensure HTTP Proxy server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled squid

echo "*********************************************************"
echo "2.2.14 Ensure SNMP server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled snmpd

echo "*********************************************************"
echo "2.2.15 Ensure mail transfer agent is configured for loca-only mode"
echo "*********************************************************"
echo ""
netstat -an | grep LIST | grep ":25[[:space:]]"

echo "*********************************************************"
echo "2.2.16 Ensure NIS server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled ypserv

echo "*********************************************************"
echo "2.2.17 Ensure rsh server is not enabled"
echo "*********************************************************"
echo ""

echo "$ systemctl is-enabled rsh.socket"
systemctl is-enabled rsh.socket

echo "$ systemctl is-enabled rlogin.socket"
systemctl is-enabled rlogin.socket

echo "$ systemctl is-enabled rexec.socket"
systemctl is-enabled rexec.socket

echo "*********************************************************"
echo "2.2.18 Ensure talk server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled ntalk

echo "*********************************************************"
echo "2.2.19 Ensure telnet server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled telnet.socket

echo "*********************************************************"
echo "2.2.20 Ensure tftp server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled tftp.socket

echo "*********************************************************"
echo "2.2.21 Ensure rsync server is not enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled rsyncd

echo "*********************************************************"
echo "******2.3 Service Clients******"
echo "*********************************************************"

echo "*********************************************************"
echo "2.3.1 Ensure NIS Client is not installed"
echo "*********************************************************"
echo ""
rpm -q ypbind

echo "*********************************************************"
echo "2.3.2 Ensure rsh client is not installed"
echo "*********************************************************"
echo ""
rpm -q rsh

echo "*********************************************************"
echo "2.3.3 Ensure talk client is not installed"
echo "*********************************************************"
echo ""
rpm -q talk

echo "*********************************************************"
echo "2.3.4 Ensure telnet client is not installed"
echo "*********************************************************"
echo ""
rpm -q telnet

echo "*********************************************************"
echo "2.3.5 Ensure LDAP client is not installed"
echo "*********************************************************"
echo ""
rpm -q openldap-clients

echo "*********************************************************"
echo "******3 Network Configuration******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "3.1 Network Parameters '(Host Only)'"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "3.1.1 Ensure IP forwarding is disabled"
echo "*********************************************************"
echo ""

echo "$ sysctl net.ipv4.ip_forward"
sysctl net.ipv4.ip_forward

echo "*********************************************************"
echo "3.1.2 Ensure packet redirect sending is disabled"
echo "*********************************************************"
echo ""

echo "$ sysctl net.ipv4.conf.all.send_redirects"
sysctl net.ipv4.conf.all.send_redirects

echo "$ sysctl net.ipv4.conf.default.send_redirects"
sysctl net.ipv4.conf.default.send_redirects 

echo "*********************************************************"
echo "******3.2 Network Parameters (Host and Router)******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "3.2.1 Check source routed packets are not accepted"
echo "*********************************************************"
echo ""

echo "$ sysctl net.ipv4.conf.all.accept_source_route"
sysctl net.ipv4.conf.all.accept_source_route

echo "$ sysctl net.ipv4.conf.default.accept_source_route"
sysctl net.ipv4.conf.default.accept_source_route

echo "*********************************************************"
echo "3.2.2 Check ICMP redicrects are not accepted"
echo "*********************************************************"
echo ""

echo "$ sysctl net.ipv4.conf.all.accept_redirects"
sysctl net.ipv4.conf.all.accept_redirects

echo "$ sysctl net.ipv4.conf.default.accept_redirects"
sysctl net.ipv4.conf.default.accept_redirects

echo "*********************************************************"
echo "3.2.3 Check secure ICMP redirects are not accepted"
echo "*********************************************************"
echo ""

echo "$ sysctl net.ipv4.conf.all.secure_redirects"
sysctl net.ipv4.conf.all.secure_redirects

echo "$ sysctl net.ipv4.conf.default.secure_redirects"
sysctl net.ipv4.conf.default.secure_redirects

echo "*********************************************************"
echo "3.2.4 Check if suspicious packets are logged"
echo "*********************************************************"
echo ""

echo "$ sysctl net.ipv4.conf.all.log_martians"
sysctl net.ipv4.conf.all.log_martians

echo "$ sysctl net.ipv4.conf.default.log_martians"
sysctl net.ipv4.conf.default.log_martians

echo "*********************************************************"
echo "3.2.5 Ensure broadcast ICMP requests are ignored"
echo "*********************************************************"
echo ""
sysctl net.ipv4.icmp_echo_ignore_broadcasts

echo "*********************************************************"
echo "3.2.6 Ensure bogus ICMP responses are ignored"
echo "*********************************************************"
echo ""
sysctl net.ipv4.icmp_ignore_bogus_error_responses

echo "*********************************************************"
echo "3.2.7 Ensure Reverse Path Filtering is enabled"
echo "*********************************************************"
echo ""

echo "$ sysctl net.ipv4.conf.all.rp_filter"
sysctl net.ipv4.conf.all.rp_filter

echo "$ sysctl net.ipv4.conf.default.rp_filter"
sysctl net.ipv4.conf.default.rp_filter

echo "*********************************************************"
echo "3.2.8 Ensure TCP SYN Cookies is enabled"
echo "*********************************************************"
echo ""
sysctl net.ipv4.tcp_syncookies

echo "*********************************************************"
echo "******3.3 IPv6******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "3.3.1 Ensure IPv6 router advertisements are not accepted"
echo "*********************************************************"
echo ""

echo "$ sysctl net.ipv6.conf.all.accept_ra"
sysctl net.ipv6.conf.all.accept_ra

echo "$ sysctl net.ipv6.conf.default.accept_ra"
sysctl net.ipv6.conf.default.accept_ra

echo "*********************************************************"
echo "3.3.2 Ensure IPv6 redirects are not accepted"
echo "*********************************************************"
echo ""

echo "$sysctl net.ipv6.conf.all.accept_redirects"
sysctl net.ipv6.conf.all.accept_redirects

echo "$ sysctl net.ipv6.conf.default.accept_redirects"
sysctl net.ipv6.conf.default.accept_redirects

echo "*********************************************************"
echo "3.3.3 Check if ipv6 is disabled"
echo "*********************************************************"
echo ""
grep "^\s*linux" /boot/grub2/grub.cfg

echo "*********************************************************"
echo "******3.4 TCP Wrappers******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "3.4.1 Ensure TCP Wrappers is installed"
echo "*********************************************************"
echo ""

echo "$ rpm -q tcp_wrappers"
rpm -q tcp_wrappers

echo "$ rpm -q tcp_wrappers-libs"
rpm -q tcp_wrappers-libs

echo "*********************************************************"
echo "3.4.2 Ensure /etc/hosts.allow is configured"
echo "*********************************************************"
echo ""
cat /etc/hosts.allow

echo "*********************************************************"
echo "3.4.3 Ensure /etc/hosts.deny is configured"
echo "*********************************************************"
echo ""
cat /etc/hosts.deny

echo "*********************************************************"
echo "3.4.4 Ensure permissions on /etc/hosts.allow are configured"
echo "*********************************************************"
echo ""
stat /etc/hosts.allow

echo "*********************************************************"
echo "3.4.5 Ensure permissions on /etc/hosts.deny are configured"
echo "*********************************************************"
echo ""
stat /etc/hosts.deny

echo "*********************************************************"
echo "******3.5 Uncommon Network Protocols******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "3.5.1 Ensure DCCP is disabled"
echo "*********************************************************"
echo ""
modprobe -n -v dccp

echo "*********************************************************"
echo "3.5.2 Ensure SCTP is disabled"
echo "*********************************************************"
echo ""
modprobe -n -v sctp

echo "*********************************************************"
echo "3.5.3 Ensure RDS is disabled"
echo "*********************************************************"
echo ""
modprobe -n -v rds

echo "*********************************************************"
echo "3.5.4 Ensure TIPC is disabled"
echo "*********************************************************"
echo ""
modprobe -n -v tipc


echo "*********************************************************"
echo "******3.6 Firewall Configuration******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "3.6.1"
echo "Check if iptables is installed"
echo "*********************************************************"
echo ""

echo "$ rpm -q iptables"
rpm -q iptables

echo "*********************************************************"
echo "3.6.2 Ensure default deny firewall policy"
echo "*********************************************************"
echo ""
iptables -L

echo "*********************************************************"
echo "3.6.3 Ensure loopback traffic is configured"
echo "*********************************************************"
echo ""
iptables -L INPUT -v -n

echo "*********************************************************"
echo "3.6.4 Ensure outbound and established connections are configured"
echo "*********************************************************"
echo ""
iptables -L -v -n

echo "*********************************************************"
echo "3.6.5 Ensure firewall rules exist for all open ports"
echo "*********************************************************"
echo ""

echo "$ netstat -ln"
netstat -ln

echo "$ iptables -L INPUT -v -n"
iptables -L INPUT -v -n

echo "*********************************************************"
echo "******3.7 Ensure wireless interfaces are disabled******"
echo "*********************************************************"
echo ""

echo "$ iwconfig"
iwconfig

echo "$ ip link show up"
ip link show up

echo "*********************************************************"
echo "******4 Logging and Auditing******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "4.1 Configure System Accounting (auditd)"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "4.1.1 Configure Data Retention"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "4.1.1.1 Ensure audit log storage size is configured"
echo "*********************************************************"
echo ""
grep max_log_file /etc/audit/auditd.conf

echo "*********************************************************"
echo "4.1.1.2 Ensure system is disabled when audit logs are full"
echo "*********************************************************"
echo ""

echo "$ grep space_left_action /etc/audit/auditd.conf"
grep space_left_action /etc/audit/auditd.conf

echo "$ grep action_mail_acct /etc/audit/auditd.conf"
grep action_mail_acct /etc/audit/auditd.conf

echo "$ grep admin_space_left_action /etc/audit/auditd.conf"
grep admin_space_left_action /etc/audit/auditd.conf

echo "*********************************************************"
echo "4.1.1.3 Ensure audit logs are not automatically deleted"
echo "*********************************************************"
echo ""
grep max_log_file_action /etc/audit/auditd.conf

echo "*********************************************************"
echo "4.1.2 Ensure auditd service is enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled auditd

echo "*********************************************************"
echo "4.1.3 Ensure auditing for processes that start prior to auditd is enabled"
echo "*********************************************************"
echo ""
grep "^\s*linux" /boot/grub2/grub.cfg

echo "*********************************************************"
echo "4.1.4 Ensure events that modify date and time information are collected"
echo "*********************************************************"
echo ""

echo "$ grep time-change /etc/audit/audit.rules"
grep time-change /etc/audit/audit.rules

echo "$ auditctl -l | grep time-change"
auditctl -l | grep time-change

echo "*********************************************************"
echo "4.1.5 Ensure events that modify user/group information are collected"
echo "*********************************************************"
echo ""

echo "$ grep identity /etc/audit/audit.rules"
grep identity /etc/audit/audit.rules

echo "$ auditctl -l | grep identity"
auditctl -l | grep identity

echo "*********************************************************"
echo "4.1.6 Ensure events that modify the system's network environment are collected"
echo "*********************************************************"
echo ""

echo "$ grep system-locale /etc/audit/audit.rules"
grep system-locale /etc/audit/audit.rules

echo "$ auditctl -l | grep system-locale"
auditctl -l | grep system-locale

echo "*********************************************************"
echo "4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected"
echo "*********************************************************"
echo ""
grep MAC-policy /etc/audit/audit.rules

echo "*********************************************************"
echo "4.1.8 Ensure login and logout events are collected"
echo "*********************************************************"
echo ""
grep logins /etc/audit/audit.rules

echo "*********************************************************"
echo "4.1.9 Ensure session initiation information is collected"
echo "*********************************************************"
echo ""

echo "$ grep session /etc/audit/audit.rules"
grep session /etc/audit/audit.rules

echo "$ auditctl -l | grep session"
auditctl -l | grep session

echo "*********************************************************"
echo "4.1.10 Ensure discretionary access control permission modification events are collected"
echo "*********************************************************"
echo ""

echo "$ grep perm_mod /etc/audit/audit.rules"
grep perm_mod /etc/audit/audit.rules

echo "$ auditctl -l | grep perm_mod"
auditctl -l | grep perm_mod

echo "*********************************************************"
echo "4.1.11 Ensure unsuccessful unauthorized file access attempts are collected"
echo "*********************************************************"
echo ""

echo "$ grep access /etc/audit/audit.rules"
grep access /etc/audit/audit.rules

echo "$ auditctl -l | grep access"
auditctl -l | grep access

echo "*********************************************************"
echo "4.1.12 Ensure use of privileged commands is collected"
echo "*********************************************************"
echo ""
find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \ "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \ -k privileged" }'

echo "*********************************************************"
echo "4.1.13 Ensure successful file system mounts are collected"
echo "*********************************************************"
echo ""

echo "$ grep mounts /etc/audit/audit.rules"
grep mounts /etc/audit/audit.rules

echo "$ auditctl -l | grep mounts"
auditctl -l | grep mounts

echo "*********************************************************"
echo "4.1.14 Ensure file deletion events by users are collected"
echo "*********************************************************"
echo ""

echo "$ grep delete /etc/audit/audit.rules"
grep delete /etc/audit/audit.rules

echo "$ auditctl -l | grep delete"
auditctl -l | grep delete

echo "*********************************************************"
echo "4.1.15 Ensure changes to system administration scope (sudoers) is collected"
echo "*********************************************************"
echo ""

echo "$ grep scope /etc/audit/audit.rules"
grep scope /etc/audit/audit.rules

echo "$ auditctl -l | grep scope"
auditctl -l | grep scope

echo "*********************************************************"
echo "4.1.16 Ensure system administrator actions (sudolog) are collected"
echo "*********************************************************"
echo ""

echo "$ grep actions /etc/audit/audit.rules"
grep actions /etc/audit/audit.rules

echo "$ auditctl -l | grep actions"
auditctl -l | grep actions

echo "*********************************************************"
echo "4.1.17 Ensure kernel module loading and unloading is collected"
echo "*********************************************************"
echo ""

echo "$ grep modules /etc/audit/audit.rules"
grep modules /etc/audit/audit.rules

echo "$ auditctl -l | grep modules"
auditctl -l | grep modules

echo "*********************************************************"
echo "4.1.18 Ensure the audit configuration is immutable"
echo "*********************************************************"
echo ""
grep "^\s*[^#]" /etc/audit/audit.rules | tail -1

echo "*********************************************************"
echo "******4.2.1 Configure rsyslog******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "4.2.1.1 Check if rsyslog is enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled rsyslog

echo "*********************************************************"
echo "4.2.1.2 Check if logging is configured"
echo "*********************************************************"
echo ""
ls -al /var/log

echo "*********************************************************"
echo "4.2.1.3 Ensure rsyslog default file permissions configured"
echo "*********************************************************"
echo ""
grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf

echo "*********************************************************"
echo "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host"
echo "*********************************************************"
echo ""
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf

echo "*********************************************************"
echo "4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts."
echo "*********************************************************"
echo ""

echo "$ grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

echo "$ grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

echo "*********************************************************"
echo "******4.2.2 Configure syslog-ng******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "4.2.2.1 Ensure syslog-ng service is enabled"
echo "*********************************************************"
echo ""
systemctl is-enabled syslog-ng

echo "*********************************************************"
echo "4.2.2.2 Ensure logging is configured"
echo "*********************************************************"
echo ""
ls -l /var/log/

echo "*********************************************************"
echo "4.2.2.3 Ensure syslog-ng default file permissions configured"
echo "*********************************************************"
echo ""
grep ^options /etc/syslog-ng/syslog-ng.conf

echo "*********************************************************"
echo "******4.2.3 Ensure rsyslog or syslog-ng is installed******"
echo "*********************************************************"
echo ""

echo "$ rpm -q rsyslog"
rpm -q rsyslog

echo "$ rpm -q syslog-ng"
rpm -q syslog-ng

echo "*********************************************************"
echo "******4.2.4 Ensure permissions on all logfiles are configured******"
echo "*********************************************************"
echo ""
find /var/log -type f -ls

echo "*********************************************************"
echo "******5.1.1 Ensure cron daemon is enabled******"
echo "*********************************************************"
echo ""
systemctl is-enabled crond

echo "*********************************************************"
echo "******5.1.2 Ensure permissions on /etc/crontab are configured******"
echo "*********************************************************"
echo ""
stat /etc/crontab

echo "*********************************************************"
echo "******5.1.3 Ensure permissions on /etc/cron.hourly are configured******"
echo "*********************************************************"
echo ""
stat /etc/cron.hourly

echo "*********************************************************"
echo "******5.1.4 Ensure permissions on /etc/cron.daily are configured******"
echo "*********************************************************"
echo ""
stat /etc/cron.daily

echo "*********************************************************"
echo "******5.1.5 Ensure permissions on /etc/cron.weekly are configured******"
echo "*********************************************************"
echo ""
stat /etc/cron.weekly

echo "*********************************************************"
echo "******5.1.6 Ensure permissions on /etc/cron.monthly are configured******"
echo "*********************************************************"
echo ""
stat /etc/cron.monthly

echo "*********************************************************"
echo "******5.1.7 Ensure permissions on /etc/cron.d are configured******"
echo "*********************************************************"
echo ""
stat /etc/cron.d

echo "*********************************************************"
echo "******5.1.8 Ensure at/cron is restricted to authorized users******"
echo "*********************************************************"
echo ""

echo "$ stat /etc/cron.deny"
stat /etc/cron.deny

echo "$ stat /etc/at.deny"
stat /etc/at.deny

echo "*********************************************************"
echo "******5.2 SSH Server Configuration******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "5.2.1 Check if permissions on /etc/ssh/sshd_config are configured"
echo "*********************************************************"
echo ""
stat /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.2 Check if SSH protocal is set to 2"
echo "*********************************************************"
echo ""
grep "^Protocol" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.3 Check if SSH LogLevel is set to INFO"
echo "*********************************************************"
echo ""
grep "^LogLevel" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.4 Check if SSH X11 forwarding is disabled"
echo "*********************************************************"
echo ""
grep "^X11Forwarding" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less"
echo "*********************************************************"
echo ""
grep "^MaxAuthTries" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.6 Ensure SSH IgnoreRhosts is enabled"
echo "*********************************************************"
echo ""
grep "^IgnoreRhosts" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.7 Ensure SSH HostbasedAuthentication is disabled"
echo "*********************************************************"
echo ""
grep "^HostbasedAuthentication" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.8 Ensure SSH root login is disabled"
echo "*********************************************************"
echo ""
grep "^PermitRootLogin" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.9 Ensure SSH PermitEmptyPasswords is disabled"
echo "*********************************************************"
echo ""
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.10 Ensure SSH PermitUserEnvironment is disabled"
echo "*********************************************************"
echo ""
grep PermitUserEnvironment /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.11 Ensure only approved MAC algorithms are used"
echo "*********************************************************"
echo ""
grep "MACs" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.12 Ensure SSH Idle Timeout Interval is configured"
echo "*********************************************************"
echo ""

echo "$ grep "^ClientAliveInterval" /etc/ssh/sshd_config"
grep "^ClientAliveInterval" /etc/ssh/sshd_config

echo "$ grep "^ClientAliveCountMax" /etc/ssh/sshd_config"
grep "^ClientAliveCountMax" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.13 Ensure SSH LoginGraceTime is set to one minute or less"
echo "*********************************************************"
echo ""
grep "^LoginGraceTime" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.14 Ensure SSH access is limited"
echo "*********************************************************"
echo ""

echo "$ grep "^AllowUsers" /etc/ssh/sshd_config"
grep "^AllowUsers" /etc/ssh/sshd_config

echo "$ grep "^AllowGroups" /etc/ssh/sshd_config"
grep "^AllowGroups" /etc/ssh/sshd_config

echo "$ grep "^DenyUsers" /etc/ssh/sshd_config"
grep "^DenyUsers" /etc/ssh/sshd_config

echo "$ grep "^DenyGroups" /etc/ssh/sshd_config"
grep "^DenyGroups" /etc/ssh/sshd_config

echo "*********************************************************"
echo "5.2.15 Ensure SSH warning banner is configured"
echo "*********************************************************"
echo ""
grep "^Banner" /etc/ssh/sshd_config

echo "*********************************************************"
echo "******5.3 Configure PAM******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "5.3.1 Ensure password creation requirements are configured"
echo "*********************************************************"
echo ""

echo "$ grep pam_pwquality.so /etc/pam.d/password-auth"
grep pam_pwquality.so /etc/pam.d/password-auth

echo "$ grep pam_pwquality.so /etc/pam.d/system-auth"
grep pam_pwquality.so /etc/pam.d/system-auth

echo "$ grep ^minlen /etc/security/pwquality.conf"
grep ^minlen /etc/security/pwquality.conf

echo "$ grep ^dcredit /etc/security/pwquality.conf"
grep ^dcredit /etc/security/pwquality.conf

echo "$ grep ^lcredit /etc/security/pwquality.conf"
grep ^lcredit /etc/security/pwquality.conf

echo "$ grep ^ocredit /etc/security/pwquality.conf"
grep ^ocredit /etc/security/pwquality.conf

echo "$ grep ^ucredit /etc/security/pwquality.conf"
grep ^ucredit /etc/security/pwquality.conf

echo "*********************************************************"
echo "5.3.3 Ensure password reuse is limited"
echo "*********************************************************"
echo ""

echo "$ egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth

echo "$ egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth

echo "*********************************************************"
echo "5.3.4 Ensure password hashing algorithm is SHA-512"
echo "*********************************************************"
echo ""

echo "$ egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth

echo "$ egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth"
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth

echo "*********************************************************"
echo "******5.4.1 Set Shadow Password Suite Parameters******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "5.4.1.1 Ensure password expiration is 365 days or less"
echo "*********************************************************"
echo ""
grep PASS_MAX_DAYS /etc/login.defs

echo "*********************************************************"
echo "5.4.1.2 Ensure minimum days between password changes is 7 or more"
echo "*********************************************************"
echo ""
grep PASS_MIN_DAYS /etc/login.defs

echo "*********************************************************"
echo "5.4.1.3 Ensure password expiration warning days is 7 or more"
echo "*********************************************************"
echo ""
grep PASS_WARN_AGE /etc/login.defs

echo "*********************************************************"
echo "5.4.1.4 Ensure inactive password lock is 30 days or less"
echo "*********************************************************"
echo ""
useradd -D | grep INACTIVE

echo "*********************************************************"
echo "5.4.1.5 Ensure all users last password change date is in the past"
echo "*********************************************************"
echo ""
cat /etc/shadow | cut -d: -f1

echo "*********************************************************"
echo "******5.4.2 Ensure system accounts are non-login******"
echo "*********************************************************"
echo ""
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}'

echo "*********************************************************"
echo "******5.4.3 Ensure default group for the root account is GID 0******"
echo "*********************************************************"
echo ""
grep "^root:" /etc/passwd | cut -f4 -d:

echo "*********************************************************"
echo "******5.4.4 Ensure default user umask is 027 or more restrictive******"
echo "*********************************************************"
echo ""
echo "$ grep "umask" /etc/bashrc"
grep "umask" /etc/bashrc

echo "$ grep "umask" /etc/profile /etc/profile.d/*.sh"
grep "umask" /etc/profile /etc/profile.d/*.sh

echo "*********************************************************"
echo "******5.4.5 Ensure default user shell timeout is 900 seconds or less******"
echo "*********************************************************"
echo ""
echo "$ grep "^TMOUT" /etc/bashrc"
grep "^TMOUT" /etc/bashrc

echo "$ grep "^TMOUT" /etc/profile"
grep "^TMOUT" /etc/profile

echo "*********************************************************"
echo "******5.5 Ensure root login is restricted to system console******"
echo "*********************************************************"
echo ""
cat /etc/securetty

echo "*********************************************************"
echo "******5.6 Ensure access to the su command is restricted******"
echo "*********************************************************"
echo ""

echo "4 grep pam_wheel.so /etc/pam.d/su"
grep pam_wheel.so /etc/pam.d/su

echo "$ grep wheel /etc/group"
grep wheel /etc/group

echo "*********************************************************"
echo "******6.1 System File Permissions******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "6.1.1 Audit system file permissions"
echo "*********************************************************"
echo ""
rpm -qf /bin/bash

echo "*********************************************************"
echo "6.1.2 Check if permissions on /etc/passwd are configured"
echo "*********************************************************"
echo ""
stat /etc/passwd

echo "*********************************************************"
echo "6.1.3 Check if permissions on /etc/shadow are configured"
echo "*********************************************************"
echo ""
stat /etc/shadow

echo "*********************************************************"
echo "6.1.4 Check if permissions on /etc/group are configured"
echo "*********************************************************"
echo ""
stat /etc/group

echo "*********************************************************"
echo "6.1.5 Check if permissions on /etc/gshadow are configured"
echo "*********************************************************"
echo ""
stat /etc/gshadow

echo "*********************************************************"
echo "6.1.6 Check if permissions on /etc/passwd- are configured"
echo "*********************************************************"
echo ""
stat /etc/passwd-

echo "*********************************************************"
echo "6.1.7 Check if permissions on /etc/shadow- are configured"
echo "*********************************************************"
echo ""
stat /etc/shadow-

echo "*********************************************************"
echo "6.1.8 Check if permissions on /etc/group- are configured"
echo "*********************************************************"
echo ""
stat /etc/group-

echo "*********************************************************"
echo "6.1.9 Check if permissions on /etc/gshadow- are configured"
echo "*********************************************************"
echo ""
stat /etc/gshadow-

echo "*********************************************************"
echo "6.1.10 Ensure no world writable files exist"
echo "*********************************************************"
echo ""
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002

echo "*********************************************************"
echo "6.1.11 Ensure no unowned files or directories exist"
echo "*********************************************************"
echo ""
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser

echo "*********************************************************"
echo "6.1.12 Ensure no ungrouped files or directories exist"
echo "*********************************************************"
echo ""
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup

echo "*********************************************************"
echo "6.1.13 Audit SUID executables"
echo "*********************************************************"
echo ""
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000

echo "*********************************************************"
echo "6.1.14 Audit SGID executables"
echo "*********************************************************"
echo ""
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000

echo "*********************************************************"
echo "******6.2 User and Group Settings******"
echo "*********************************************************"
echo ""

echo "*********************************************************"
echo "6.2.1 Ensure password fields are not empty"
echo "*********************************************************"
echo ""
cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'

echo "*********************************************************"
echo "6.2.2 Ensure no legacy "+" entries exist in /etc/passwd"
echo "*********************************************************"
echo ""
grep '^\+:' /etc/passwd

echo "*********************************************************"
echo "6.2.3 Ensure no legacy "+" entries exist in /etc/shadow"
echo "*********************************************************"
echo ""
grep '^\+:' /etc/shadow

echo "*********************************************************"
echo "6.2.4 Ensure no legacy "+" entries exist in /etc/group"
echo "*********************************************************"
echo ""
grep '^\+:' /etc/group

echo "*********************************************************"
echo "6.2.5 Ensure root is the only UID 0 account"
echo "*********************************************************"
echo ""
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'

echo "*********************************************************"
echo "********************END OF SCRIPT************************"
echo "*********************************************************"