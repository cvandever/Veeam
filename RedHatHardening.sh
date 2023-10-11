#!/usr/bin/env bash

# Set defaults
LOG=install.log
GREEN='\e[01;32m'
NOCOLOR='\033[0m'

# Define function to print current job
print_job() {
  printf "${GREEN} [+] ${1} ${NOCOLOR}\n"
}

# Define function to run system commands
run_cmd() {
  # Redirect stdout and stderr to $LOG
  eval "$1" >> $LOG 2>&1 && return 0 # success
}

# Define function to modify file
function update_file() {
  local pattern="$1"
  local replacement="$2"
  local file="$3"
  sed -i.bak "s|${pattern}|${replacement}|g" "${file}"
  sed -i.bak "/^[[:space:]]*$/d" "${file}"
}

# Define a function to update the audit rules file
function update_audit_rules() {
  local rule="$1"
  local new_rule="$2"
  local file="$3"
  sed -i "s|${rule}|${new_rule}|g" "${file}"
}

STIG_RULES_FILE=/etc/audit/rules.d/audit.rules
SSH_CONFIG_FILE=/etc/ssh/sshd_config

# Clear $LOG
> $LOG
export DEBIAN_FRONTEND=noninteractive
clear
print_job "Veeam DISA STIG automated hardening process started"

print_job "yum update and upgrade"
run_cmd "yum update -y"

# install/remove services
print_job "V-238200: operating system must allow users to directly initiate a session lock for all connection types"
run_cmd "yum install -y vlock"

print_job "V-238371: operating system must use a file integrity tool to verify correct operation of all security functions"
run_cmd "yum install -y aide"

print_job "V-238298: operating system must produce audit records and reports containing information"
run_cmd "yum install -y audit"
run_cmd "systemctl enable auditd.service"

print_job "V-238326: operating system must not have the telnet package installed"
run_cmd "yum remove -y telnet"

print_job "V-238327: operating system must not have the rsh-server package installed"
run_cmd "yum remove -y rsh-server"

print_job "V-238353: operating system must be configured to preserve log records from failure events"
run_cmd "yum install -y rsyslog"
run_cmd "systemctl enable --now rsyslog"

print_job "V-238354: operating system must have an application firewall installed in order to control remote access methods"
run_cmd "yum install -y firewalld"

print_job "V-238360: operating system must be configured to use AppArmor"
run_cmd "yum install -y apparmor"
run_cmd "systemctl enable --now apparmor.service"

# additional services required to be installed but not mentioned
run_cmd "yum install -y libpwquality"
run_cmd "yum install -y chrony"

# configuration
print_job "V-238202: operating system must enforce 24 hours/1 day as the minimum password lifetime"
update_file "^.PASS_MIN_DAYS.$" "PASS_MIN_DAYS 1" /etc/login.defs

print_job "V-238203: operating system must enforce a 60-day maximum password lifetime restriction"
update_file "^.PASS_MAX_DAYS.$" "PASS_MAX_DAYS 60" /etc/login.defs

print_job "V-238207: operating system must automatically terminate a user session after inactivity timeouts have expired"
update_file "^.TMOUT.$" "TMOUT=600" /etc/profile

print_job "V-238208: operating system must require users to reauthenticate for privilege escalation or when changing roles"
update_file "NOPASSWD" "" /etc/sudoers /etc/sudoers.d/*
update_file "!authenticate" "" /etc/sudoers /etc/sudoers.d/*

print_job "V-238209: operating system default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files"
update_file "^.UMASK.$" "UMASK 077" /etc/login.defs

print_job "V-238211: operating system must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions"
update_file "^.UsePAM.$" "UsePAM yes" $SSH_CONFIG_FILE

print_job "V-238212: operating system must immediately terminate all network connections associated with SSH traffic after a period of inactivity"
update_file "^.ClientAliveCountMax.$" "ClientAliveCountMax 1" $SSH_CONFIG_FILE

print_job "V-238213: operating system must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity"
update_file "^.ClientAliveInterval.$" "ClientAliveInterval 600" $SSH_CONFIG_FILE

print_job "V-238214: operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting any local or remote connection to the system"
update_file "^.Banner.$" "Banner /etc/issue.net" $SSH_CONFIG_FILE
echo -e "WARNING: Unauthorized access to this system is forbidden and will be prosecuted by law. By accessing this system, you agree that your actions may be monitored if unauthorized usage is suspected\n" > /etc/issue.net
echo -e "WARNING: Unauthorized access to this system is forbidden and will be prosecuted by law. By accessing this system, you agree that your actions may be monitored if unauthorized usage is suspected\n" >> /etc/issue

print_job "V-238216: operating system must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hashes"
update_file "^.*MACs.*$" "MACs hmac-sha2-512,hmac-sha2-256" $SSH_CONFIG_FILE

print_job "V-238218: operating system must not allow unattended or automatic login via SSH"
update_file "^.*PermitEmptyPasswords.*$" "PermitEmptyPasswords no" $SSH_CONFIG_FILE
update_file "^.*PermitUserEnvironment.*$" "PermitUserEnvironment no" $SSH_CONFIG_FILE

print_job "V-238219: operating system must be configured so that remote X connections are disabled"
update_file "^.*X11Forwarding.*$" "X11Forwarding no" $SSH_CONFIG_FILE

print_job "V-238220: operating system SSH daemon must prevent remote hosts from connecting to the proxy display"
update_file "^.*X11UseLocalhost.*$" "X11UseLocalhost yes" $SSH_CONFIG_FILE

print_job "V-238221: operating system must enforce password complexity by requiring that at least one upper-case character be used"
update_file "^.*ucredit.*$" "ucredit=-1" /etc/security/pwquality.conf 
update_file "^.*lcredit.*$" "lcredit=-1" /etc/security/pwquality.conf
update_file "^.*dcredit.*$" "dcredit=-1" /etc/security/pwquality.conf
update_file "^.*difok.*$" "difok=8" /etc/security/pwquality.conf
update_file "^.*minlen.*$" "minlen=15" /etc/security/pwquality.conf
update_file "^.*ocredit.*$" "ocredit=-1" /etc/security/pwquality.conf
update_file "^.*dictcheck.*$" "dictcheck=1" /etc/security/pwquality.conf
update_file "^.*enforcing.*$" "enforcing = 1" /etc/security/pwquality.conf

print_job "V-238235: operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made"
update_file "^.*audit.*$" "audit" /etc/security/faillock.conf
update_file "^.*silent.*$" "silent" /etc/security/faillock.conf
update_file "^.*deny.*$" "deny = 3" /etc/security/faillock.conf
update_file "^.*fail_interval.*$" "fail_interval = 900" /etc/security/faillock.conf
update_file "^.*unlock_time.*$" "unlock_time = 0" /etc/security/faillock.conf

print_job "V-238236: operating system must be configured so that the script which runs each 30 days or less to check file integrity is the default one"
yum install aide
cp -f /usr/sbin/aide /etc/cron.daily/aide

print_job "V-238237: operating system must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt"
update_file "^.*auth[[:space:]]*required[[:space:]]*pam_faildelay.so.*$" "auth    required    pam_faildelay.so    delay=4000000" /etc/login.defs

print_job "V-238238: operating system must generate audit rules for account creation/modification/termination that affects /etc/passwd"
update_audit_rules "^.*-w[[:space:]]*\/etc\/passwd[[:space:]]*-p[[:space:]]*wa[[:space:]]*-k[[:space:]]*usergroup_modification.*$" "-w /etc/passwd -p wa -k usergroup_modification" $STIG_RULES_FILE

print_job "V-238239: operating system must generate audit rules for account creation/modification/termination that affects /etc/group"
update_file "^.*-w[[:space:]]*\/etc\/group[[:space:]]*-p[[:space:]]*wa[[:space:]]*-k[[:space:]]*usergroup_modification.*$" "-w /etc/group -p wa -k usergroup_modification" $STIG_RULES_FILE

print_job "V-238240: operating system must generate audit rules for modification in /etc/shadow"
update_file "^.*-w[[:space:]]*\/etc\/shadow[[:space:]]*-p[[:space:]]*wa[[:space:]]*-k[[:space:]]*usergroup_modification.*$" "-w /etc/shadow -p wa -k usergroup_modification" $STIG_RULES_FILE

print_job "V-238241: operating system must generate audit rules for modification in /etc/gshadow"
update_file "^.*-w[[:space:]]*\/etc\/gshadow[[:space:]]*-p[[:space:]]*wa[[:space:]]*-k[[:space:]]*usergroup_modification.*$" "-w /etc/gshadow -p wa -k usergroup_modification" $STIG_RULES_FILE

print_job "V-238242: operating system must generate audit rules for modification in /etc/security/opasswd"
update_file "^.*-w[[:space:]]*\/etc\/security\/opasswd[[:space:]]*-p[[:space:]]*wa[[:space:]]*-k[[:space:]]*usergroup_modification.*$" "-w /etc/security/opasswd -p wa -k usergroup_modification" $STIG_RULES_FILE

print_job "V-238244: operating system must shut down by default upon audit failure"
update_file "^.*disk_full_action.*$" "disk_full_action = HALT" /etc/audit/auditd.conf

print_job "V-238245: operating system must be configured so that audit log files are not read or write-accessible by unauthorized users"
chmod 0600 /var/log/audit/*

print_job "V-238246: operating system must be configured to permit only authorized users ownership of the audit log files"
chown root /var/log/audit/*

print_job "V-238247: operating system must permit only authorized groups ownership of the audit log files"
update_file "^.*log_group.*$" "log_group = root" /etc/audit/auditd.conf

print_job "V-238248: operating system must be configured so that the audit log directory is not write-accessible by unauthorized users"
chmod -R g-w,o-rwx /var/log/audit

print_job "V-238249: operating system must be configured so that audit configuration files are not write-accessible by unauthorized users"
chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
chown root:root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*

print_job "V-238252: operating system must generate audit records for successful/unsuccessful uses of the su command"
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*path=\/bin\/su[[:space:]]*-F[[:space:]]*perm=x[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*privileged-priv_change.*$" "-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" $STIG_RULES_FILE

print_job "V-238253: operating system must generate audit records for successful/unsuccessful uses of the chfn command"
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*path=\/usr\/bin\/chfn[[:space:]]*-F[[:space:]]*perm=x[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!\=4294967295[[:space:]]*-k[[:space:]]*privileged-chfn.*$" "-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chfn" $STIG_RULES_FILE

print_job "V-238254: operating system must generate audit records for successful/unsuccessful uses of the mount command"
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*path=\/usr\/bin\/mount[[:space:]]*-F[[:space:]]*perm=x[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*privileged-mount.*$" "-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount" $STIG_RULES_FILE

print_job "V-238255: operating system must generate audit records for successful/unsuccessful uses of the umount command"
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*path=\/usr\/bin\/umount[[:space:]]*-F[[:space:]]*perm=x[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*privileged-umount.*$" "-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-umount" $STIG_RULES_FILE

print_job "V-238256: operating system must generate audit records for successful/unsuccessful uses of the ssh-agent command"
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*path=\/usr\/bin\/ssh-agent[[:space:]]*-F[[:space:]]*perm=x[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*privileged-ssh.*$" "-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh" $STIG_RULES_FILE

print_job "V-238257: operating system must generate audit records for successful/unsuccessful uses of the ssh-keysign command"
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*path=\/usr\/lib\/openssh\/ssh-keysign[[:space:]]*-F[[:space:]]*perm=x[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*privileged-ssh.*$" "-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh" $STIG_RULES_FILE

print_job "V-238258: operating system must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls"
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b32[[:space:]]*-S[[:space:]]*setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=-1[[:space:]]*-k[[:space:]]*perm_mod.*$" "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod" $STIG_RULES_FILE
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b32[[:space:]]*-S[[:space:]]*setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr[[:space:]]*-F[[:space:]]*auid=0[[:space:]]*-k[[:space:]]*perm_mod.*$" "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod" $STIG_RULES_FILE
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b64[[:space:]]*-S[[:space:]]*setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=-1[[:space:]]*-k[[:space:]]*perm_mod.*$" "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod" $STIG_RULES_FILE
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b64[[:space:]]*-S[[:space:]]*setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr[[:space:]]*-F[[:space:]]*auid=0[[:space:]]*-k[[:space:]]*perm_mod.*$" "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod" $STIG_RULES_FILE

print_job "V-238264: operating system must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls"
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b32[[:space:]]*-S[[:space:]]*chown,fchown,fchownat,lchown[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*perm_chng.*$" "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng" $STIG_RULES_FILE
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b64[[:space:]]*-S[[:space:]]*chown,fchown,fchownat,lchown[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*perm_chng.*$" "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng" $STIG_RULES_FILE

print_job "V-238268: operating system must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls"
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b32[[:space:]]*-S[[:space:]]*chmod,fchmod,fchmodat[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*perm_chng.*$" "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng" $STIG_RULES_FILE
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b64[[:space:]]*-S[[:space:]]*chmod,fchmod,fchmodat[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*perm_chng.*$" "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng" $STIG_RULES_FILE

print_job "V-238271: operating system must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls"
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b32[[:space:]]*-S[[:space:]]*creat,open,openat,open_by_handle_at,truncate,ftruncate[[:space:]]*-F[[:space:]]*exit=-EPERM[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=-1[[:space:]]*-k[[:space:]]*perm_access.*$" "-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access" $STIG_RULES_FILE
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b32[[:space:]]*-S[[:space:]]*creat,open,openat,open_by_handle_at,truncate,ftruncate[[:space:]]*-F[[:space:]]*exit=-EACCES[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=-1[[:space:]]*-k[[:space:]]*perm_access.*$" "-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access" $STIG_RULES_FILE
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b64[[:space:]]*-S[[:space:]]*creat,open,openat,open_by_handle_at,truncate,ftruncate[[:space:]]*-F[[:space:]]*exit=-EPERM[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=-1[[:space:]]*-k[[:space:]]*perm_access.*$" "-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access" $STIG_RULES_FILE
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b64[[:space:]]*-S[[:space:]]*creat,open,openat,open_by_handle_at,truncate,ftruncate[[:space:]]*-F[[:space:]]*exit=-EACCES[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=-1[[:space:]]*-k[[:space:]]*perm_access.*$" "-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access" $STIG_RULES_FILE

print_job "V-238277: operating system must generate audit records for successful/unsuccessful uses of the sudo command"
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*path=\/usr\/bin\/sudo[[:space:]]*-F[[:space:]]*perm=x[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*priv_cmd.*$" "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" $STIG_RULES_FILE


print_job "V-238278: operating system must generate audit records for successful/unsuccessful uses of the sudoedit command"
update_file "-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" "-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" $STIG_RULES_FILE

print_job "V-238279: operating system must generate audit records for successful/unsuccessful uses of the chsh command"
update_file "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" $STIG_RULES_FILE

print_job "V-238280: operating system must generate audit records for successful/unsuccessful uses of the newgrp command"
update_file "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" $STIG_RULES_FILE

print_job "V-238281: operating system must generate audit records for successful/unsuccessful uses of the chcon command"
update_file "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" $STIG_RULES_FILE

print_job "V-238282: operating system must generate audit records for successful/unsuccessful uses of the apparmor_parser command"
update_file "-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" "-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" $STIG_RULES_FILE

print_job "V-238283: operating system must generate audit records for successful/unsuccessful uses of the setfacl command"
update_file "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" $STIG_RULES_FILE

print_job "V-238284: operating system must generate audit records for successful/unsuccessful uses of the chacl command"
update_file "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" $STIG_RULES_FILE

print_job "V-238285: operating system must generate audit records for the use and modification of the tallylog file"
update_file "-w /var/log/tallylog -p wa -k logins" "-w /var/log/tallylog -p wa -k logins" $STIG_RULES_FILE

print_job "V-238286: operating system must generate audit records for the use and modification of faillog file"
update_file "-w /var/log/faillog -p wa -k logins" "-w /var/log/faillog -p wa -k logins" $STIG_RULES_FILE

print_job "V-238287: operating system must generate audit for the use and modification of the lastlog file"
update_file "-w /var/log/lastlog -p wa -k logins" "-w /var/log/lastlog -p wa -k logins" $STIG_RULES_FILE

print_job "V-238288: operating system must generate audit records for successful/unsuccessful uses of the passwd command"
update_file "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" $STIG_RULES_FILE

print_job "V-238289: operating system must generate audit records for successful/unsuccessful uses of the unix_update command"
update_file "-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update" "-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update" $STIG_RULES_FILE

print_job "V-238290: operating system must generate audit records for successful/unsuccessful uses of the gpasswd command"
update_file "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd" "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd" $STIG_RULES_FILE

print_job "V-238291: operating system must generate audit records for successful/unsuccessful uses of the chage command"
update_file "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chage" "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chage" $STIG_RULES_FILE
print_job "V-238292: operating system must generate audit records for successful/unsuccessful uses of the usermod command"
update_audit_rules "^.*-a[[:space:]]always,exit[[:space:]]-F[[:space:]]path=/usr/sbin/usermod[[:space:]]-F[[:space:]]perm=x[[:space:]]-F[[:space:]]auid>=1000[[:space:]]-F[[:space:]]auid!=4294967295[[:space:]]-k[[:space:]]privileged-usermod.$" "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod" $STIG_RULES_FILE

print_job "V-238293: operating system must generate audit records for successful/unsuccessful uses of the crontab command"
update_audit_rules "^.*-a[[:space:]]always,exit[[:space:]]-F[[:space:]]path=/usr/bin/crontab[[:space:]]-F[[:space:]]perm=x[[:space:]]-F[[:space:]]auid>=1000[[:space:]]-F[[:space:]]auid!=4294967295[[:space:]]-k[[:space:]]privileged-crontab.$" "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-crontab" $STIG_RULES_FILE

print_job "V-238294: operating system must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command"
update_audit_rules "^.*-a[[:space:]]always,exit[[:space:]]-F[[:space:]]path=/usr/sbin/pam_timestamp_check[[:space:]]-F[[:space:]]perm=x[[:space:]]-F[[:space:]]auid>=1000[[:space:]]-F[[:space:]]auid!=4294967295[[:space:]]-k[[:space:]]privileged-pam_timestamp_check.$" "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam_timestamp_check" $STIG_RULES_FILE

print_job "V-238295: operating system must generate audit records for successful/unsuccessful uses of the init_module and finit_module syscalls"
update_audit_rules "^.-a[[:space:]]always,exit[[:space:]]-F[[:space:]]arch=b32[[:space:]]-S[[:space:]]init_module,finit_module[[:space:]]-F[[:space:]]auid>=1000[[:space:]]-F[[:space:]]auid!=4294967295[[:space:]]-k[[:space:]]module_chng.$" "-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng" $STIG_RULES_FILE
update_audit_rules "^.-a[[:space:]]always,exit[[:space:]]-F[[:space:]]arch=b64[[:space:]]-S[[:space:]]init_module,finit_module[[:space:]]-F[[:space:]]auid>=1000[[:space:]]-F[[:space:]]auid!=4294967295[[:space:]]-k[[:space:]]module_chng.$" "-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng" $STIG_RULES_FILE

print_job "V-238297: operating system must generate audit records for successful/unsuccessful uses of the delete_module syscall"
update_audit_rules "^.-a[[:space:]]always,exit[[:space:]]-F[[:space:]]arch=b32[[:space:]]-S[[:space:]]delete_module[[:space:]]-F[[:space:]]auid>=1000[[:space:]]-F[[:space:]]auid!=4294967295[[:space:]]-k[[:space:]]module_chng.$" "-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng" $STIG_RULES_FILE
update_audit_rules "^.-a[[:space:]]always,exit[[:space:]]-F[[:space:]]arch=b64[[:space:]]-S[[:space:]]delete_module[[:space:]]-F[[:space:]]auid>=1000[[:space:]]-F[[:space:]]auid!=4294967295[[:space:]]-k[[:space:]]module_chng.$" "-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng" $STIG_RULES_FILE

# Update grub configuration
print_job "V-238299: operating system must initiate session audits at system start-up"
update_file "GRUB_CMDLINE_LINUX=\"audit=1\"" "GRUB_CMDLINE_LINUX=\"audit=1\"" /etc/default/grub
run_cmd "grub2-mkconfig -o /boot/grub2/grub.cfg"

# Configure audit tools
print_job "V-238300: operating system must configure audit tools with a mode of 0755 or less permissive"
run_cmd "chmod 755 /sbin/au*"

print_job "V-238301: operating system must configure audit tools to be owned by root"
run_cmd "chown root /sbin/au*"

print_job "V-238302: operating system must configure the audit tools to be group-owned by root"
run_cmd "chown :root /sbin/au*"

print_job "V-238303: operating system must use cryptographic mechanisms to protect the integrity of audit tools"
update_file "^.*\/sbin\/auditctl.*$" "/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" /etc/aide.conf
update_file "^.*\/sbin\/auditd.*$" "/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512 " /etc/aide.conf
update_file "^.*\/sbin\/ausearch.*$" "/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" /etc/aide.conf
update_file "^.*\/sbin\/aureport.*$" "/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" /etc/aide.conf
update_file "^.*\/sbin\/autrace.*$" "/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512 " /etc/aide.conf
update_file "^.*\/sbin\/audispd.*$" "/sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512 " /etc/aide.conf
update_file "^.*\/sbin\/augenrules.*$" "/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" /etc/aide.conf

print_job "V-238304: operating system must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions"
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b64[[:space:]]*-S[[:space:]]*execve[[:space:]]*-C[[:space:]]*uid!=euid[[:space:]]*-F[[:space:]]*euid=0[[:space:]]*-F[[:space:]]*key=execpriv.*$" "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv" $STIG_RULES_FILE
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b64[[:space:]]*-S[[:space:]]*execve[[:space:]]*-C[[:space:]]*gid!=egid[[:space:]]*-F[[:space:]]*egid=0[[:space:]]*-F[[:space:]]*key=execpriv.*$" "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv" $STIG_RULES_FILE
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b32[[:space:]]*-S[[:space:]]*execve[[:space:]]*-C[[:space:]]*uid!=euid[[:space:]]*-F[[:space:]]*euid=0[[:space:]]*-F[[:space:]]*key=execpriv.*$" "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv" $STIG_RULES_FILE
update_audit_rules "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b32[[:space:]]*-S[[:space:]]*execve[[:space:]]*-C[[:space:]]*gid!=egid[[:space:]]*-F[[:space:]]*egid=0[[:space:]]*-F[[:space:]]*key=execpriv.*$" "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv" $STIG_RULES_FILE

print_job "V-238308: operating system must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT)"
run_cmd "timedatectl set-timezone UTC"

print_job "V-238309: operating system must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access"
update_file "^.*-w[[:space:]]*\/var\/log\/sudo.log[[:space:]]*-p[[:space:]]*wa[[:space:]]*-k[[:space:]]*maintenance.*$" "-w /var/log/sudo.log -p wa -k maintenance" $STIG_RULES_FILE

print_job "V-238310: operating system must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls"
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b64[[:space:]]*-S[[:space:]]*unlink,unlinkat,rename,renameat,rmdir[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*delete.*$" "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete" $STIG_RULES_FILE
update_file "^.*-a[[:space:]]*always,exit[[:space:]]*-F[[:space:]]*arch=b32[[:space:]]*-S[[:space:]]*unlink,unlinkat,rename,renameat,rmdir[[:space:]]*-F[[:space:]]*auid>=1000[[:space:]]*-F[[:space:]]*auid!=4294967295[[:space:]]*-k[[:space:]]*delete.*$" "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete" $STIG_RULES_FILE

print_job "V-238315: operating system must generate audit records for the /var/log/wtmp file"
update_file "^.*-w[[:space:]]*\/var\/log\/wtmp[[:space:]]*-p[[:space:]]*wa[[:space:]]*-k[[:space:]]*logins.*$" "-w /var/log/wtmp -p wa -k logins" $STIG_RULES_FILE 

print_job "V-238316: operating system must generate audit records for the /var/run/wtmp file"
update_file "^.*-w[[:space:]]*\/var\/run\/wtmp[[:space:]]*-p[[:space:]]*wa[[:space:]]*-k[[:space:]]*logins.*$" "-w /var/run/wtmp -p wa -k logins" $STIG_RULES_FILE

print_job "V-238317: operating system must generate audit records for the /var/log/btmp file"
update_file "^.*-w[[:space:]]*\/var\/log\/btmp[[:space:]]*-p[[:space:]]*wa[[:space:]]*-k[[:space:]]*logins.*$" "-w /var/log/btmp -p wa -k logins" $STIG_RULES_FILE 

print_job "V-238318: operating system must generate audit records when successful/unsuccessful attempts to use modprobe command"
update_file "^.*-w[[:space:]]*\/sbin\/modprobe[[:space:]]*-p[[:space:]]*x[[:space:]]*-k[[:space:]]*modules.*$" "-w /sbin/modprobe -p x -k modules" $STIG_RULES_FILE

print_job "V-238319: operating system must generate audit records when successful/unsuccessful attempts to use the kmod command"
update_file "^.*-w[[:space:]]*\/bin\/kmod[[:space:]]*-p[[:space:]]*x[[:space:]]*-k[[:space:]]*modules.*$" "-w /bin/kmod -p x -k modules" $STIG_RULES_FILE

print_job "V-238320: operating system must generate audit records when successful/unsuccessful attempts to use the fdisk command"
update_file "^.*-w[[:space:]]*\/usr\/sbin\/fdisk[[:space:]]*-p[[:space:]]*x[[:space:]]*-k[[:space:]]*fdisk.*$" "-w /usr/sbin/fdisk -p x -k fdisk" $STIG_RULES_FILE

print_job "V-238323: operating system must limit the number of concurrent sessions to ten for all accounts and/or account types"
update_file "^.*\*[[:space:]]*hard[[:space:]]*maxlogins[[:space:]]*10.*$" "* hard maxlogins 10" /etc/security/limits.conf

print_job "V-238324: operating system must monitor remote access methods"
update_file "^.*auth\.\*,authpriv\.\*[[:space:]]*\/var\/log\/secure.*$" "auth.*,authpriv.* /var/log/secure" /etc/rsyslog.conf
update_file "^.*daemon\.\*[[:space:]]*\/var\/log\/messages.*$" "daemon.* /var/log/messages" /etc/rsyslog.conf

print_job "V-238325: operating system must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm"
update_file "^.*ENCRYPT_METHOD.*$" "ENCRYPT_METHOD SHA512" /etc/login.defs
print_job "V-238328: operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments"

#deny incoming, allow outgoing
run_cmd "firewall-cmd --set-default-zone=drop"
run_cmd "firewall-cmd --permanent --add-service=ssh"
run_cmd "firewall-cmd --reload"

print_job "V-238329: operating system must prevent direct login into the root account"
run_cmd "usermod -L root"

print_job "V-238332: operating system must set a sticky bit on all public directories"
run_cmd "find / -type d -perm -002 ! -perm -1000 -exec chmod +t '{}' \;"

print_job "V-238333: operating system must be configured to use TCP syncookies"
run_cmd "sysctl -w net.ipv4.tcp_syncookies=1"

print_job "V-238334: operating system must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail"
run_cmd "systemctl disable kdump.service"

print_job "V-238337: operating system must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries"
run_cmd "find /var/log -perm /137 -type f -exec chmod 640 '{}' \;"

print_job "V-238338: operating system must configure the /var/log directory to be group-owned by syslog"
run_cmd "chgrp syslog /var/log"

print_job "V-238339: operating system must configure the /var/log directory to be owned by root"
run_cmd "chown root /var/log"

print_job "V-238340: operating system must configure the /var/log directory to have mode 0750 or less permissive"
run_cmd "chmod 0750 /var/log"

print_job "V-238341: operating system must configure the /var/log/messages file to be group-owned by adm"
run_cmd "chgrp adm /var/log/messages"

print_job "V-238342: operating system must configure /var/log/messages file to be owned by syslog"
run_cmd "chown syslog /var/log/messages"

print_job "V-238343: operating system must configure /var/log/messages file with mode 0640 or less permissive"
run_cmd "chmod 0640 /var/log/messages"

print_job "V-238344: operating system must have directories that contain system commands set to a mode of 0755 or less permissive"
run_cmd "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec chmod -R 755 '{}' \;"

print_job "V-238345: operating system must have directories that contain system commands owned by root"
run_cmd "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec chown root '{}' \;"

print_job "V-238346: operating system must have directories that contain system commands group-owned by root"
run_cmd "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec chgrp root '{}' \;"

print_job "V-238347: operating system library files must have mode 0755 or less permissive"
run_cmd "find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \;"

print_job "V-238348: operating system library directories must have mode 0755 or less permissive"
run_cmd "find /lib /lib64 /usr/lib -perm /022 -type d -exec chmod 755 '{}' \;"

print_job "V-238349: operating system library files must be owned by root"
run_cmd "find /lib /usr/lib /lib64 ! -user root -type f -exec chown root '{}' \;"

print_job "V-238350: operating system library directories must be owned by root"
run_cmd "find /lib /usr/lib /lib64 ! -user root -type d -exec chown root '{}' \;"

print_job "V-238351: operating system library files must be group-owned by root or a system account"
run_cmd "find /lib /usr/lib /lib64 ! -group root -type f -exec chgrp root '{}' \;"

print_job "V-238352: operating system library directories must be group-owned by root"
run_cmd "find /lib /usr/lib /lib64 ! -group root -type d -exec chgrp root '{}' \;"

print_job "V-238355: operating system must enable and run the uncomplicated firewall(ufw)"
run_cmd "systemctl enable --now firewalld.service"

print_job "V-238356: operating system must, for networked systems, compare internal information system clocks at least every 24 hours with a server"
echo "server tick.usno.navy.mil iburst maxpoll 16" > /etc/chrony.conf
echo "server tock.usno.navy.mil iburst maxpoll 16" >> /etc/chrony.conf
echo "server ntp2.usno.navy.mil iburst maxpoll 16" >> /etc/chrony.conf
update_file "^.*DAEMON_OPTS.*$" "DAEMON_OPTS=\"-R -F -1\"" /etc/sysconfig/chronyd

print_job "V-238358: operating system must notify designated personnel if baseline configurations are changed in an unauthorized manner"
update_file "^.*SILENTREPORTS.*$" "SILENTREPORTS=no" /etc/aide.conf 

print_job "V-238359: operating system's Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization"
update_file "^.*gpgcheck.*$" "gpgcheck=1" /etc/yum.conf
update_file "^.*localpkg_gpgcheck.*$" "localpkg_gpgcheck=1" /etc/yum.conf
update_file "^.*repo_gpgcheck.*$" "repo_gpgcheck=1" /etc/yum.conf

print_job "V-238369: operating system must implement address space layout randomization to protect its memory from unauthorized code execution"
update_file "^.*kernel.randomize_va_space.*$" "kernel.randomize_va_space=2" /etc/sysctl.conf
run_cmd "sysctl --system"

print_job "V-238370: operating system must be configured so that Advance Package Tool (APT) removes all software components after updated versions have been installed"
update_file "^.*clean_requirements_on_remove.*$" "clean_requirements_on_remove=1" /etc/dnf/dnf.conf

print_job "V-238373: operating system must display the date and time of the last successful account logon upon logon"
update_file "^.*session[[:space:]]*required[[:space:]]*pam_lastlog.so[[:space:]]*showfailed.*$" "session    required    pam_lastlog.so showfailed" /etc/pam.d/login

print_job "V-238376: operating system must have system commands set to a mode of 0755 or less permissive"
run_cmd "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \;"

print_job "V-238377: operating system must have system commands owned by root or a system account"
run_cmd "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec chown root '{}' \;"

print_job "V-238378: operating system must have system commands group-owned by root or a system account"
run_cmd "find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec chgrp root '{}' \;"

print_job "V-238380: operating system must disable the x86 Ctrl-Alt-Delete key sequence"
run_cmd "systemctl mask ctrl-alt-del.target"
run_cmd "systemctl daemon-reload"

print_job "V-251504: operating system must not allow accounts configured with blank or null passwords"
update_file "^.*nullok.*$" "" /etc/pam.d/system-auth

print_job "V-251505: operating system must disable automatic mounting of Universal Serial Bus (USB) mass storage driver"
run_cmd "echo install usb-storage /bin/true >> /etc/modprobe.d/DISASTIG.conf"
run_cmd "echo blacklist usb-storage >> /etc/modprobe.d/DISASTIG.conf"

# restart services to apply changes 
# sshd 
run_cmd "systemctl restart sshd.service"

# auditd
run_cmd "systemctl restart auditd.service"

# firewalld
run_cmd "systemctl restart firewalld.service"

# chrony
run_cmd "systemctl restart chronyd.service"

# load audit rules
augenrules --load
