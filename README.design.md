Linux Audit Subsystem Rework Design Document
=============================================================================
https://github.com/pcmoore/misc-linux_kernel/tree/working-audit_rework_v1

*LAST UPDATED: April 27, 2022*

This document serves as the design blueprint for phase one of the Linux Audit
Rework effort.  In phase one the focus is on preparing the kernel for future
work, this is mainly focused on breaking the ties between the audit data being
recorded and the format used to represent the data.  Future work will use this
separation to introduce new audit record formats, APIs, and other improvements
intended to help improve the quality, robustness, usefulness, and performance
of Linux Audit.

## Design Goals

In an effort to keep the phase one effort focused, and resist the urge to pull
in work items from future phases, the following minimum requirements are
described in addition to a number of work items which are explicitly not part
of the phase one development.

### Requirements

In the requirements below, the terms **SHOULD**, **MUST**, **SHOULD NOT**, and
**MUST NOT** are used with similar meaning as in
[IETF RFCs](https://datatracker.ietf.org/doc/html/rfc2119).

- There **MUST** be no change to the kernel/userspace ABI, existing userspace
tooling should work the same across these changes and no new userspace tools
will be required for this work.  Future efforts will build upon this work to
expand on the ABI to support a netlink attribute based API, but that is out of
scope for this initial effort.

- There **SHOULD** be little to no performance impact on the execution threads
which generate audit events.  In fact, it is expected that performance for
audit event generating threads should improve slightly as record generation is
moved out of the critical path.  However, there is expected to be an increase
in time spent in the kauditd queue servicing kernel thread as it will now be
responsible for generating audit records as well as publishing those records to
userspace; this is believed to be a reasonable trade-off as overall
application/system performance should be improved.

- Kernel subsystems which generate audit records via the kernel audit API
**SHOULD NOT** have any knowledge of the audit record format, and **MUST NOT**
be able to affect the audit record format beyond the inclusion of the data
being recorded.

- The new kernel audit API **SHOULD** validate the data passed to it with
respect to the given field.  As an example, whenever possible C type checking
should be leveraged to catch mistakes at compile time.

- The new kernel audit API **MUST** provide a mechanism for extending the
lifetime of data passed to it beyond the immediate scope of the caller; this
**SHOULD** include techniques such as reference counting in addition to object
duplication.  This is necessary to generate the audit event messages in a
different execution context.

- The new kernel audit API **MUST** contain all necessary pre-processing of
the data passed to it such that when audit is disabled at kernel build-time
there is no impact to the caller.

### Out of Scope

- Changes to the kernel/userspace ABI as well as the on-disk audit record
format are beyond the scope of this effort.  Future work will address these
problem areas.

- Changes to the audit filtering engine and file watch mechanism are reserved
for future work.  Any changes made in these areas will only be to support the
requirements listed above.

- While this work is expected to improve overall system performance, extensive
performance analysis is reserved for future work.

## Audit API for Kernel Subsystems

The goal of the new audit API for kernel subsystems it to separate the data
from its formatting, both to support new audit record formats and help limit
incorrect use of the API.

### Data Structures

*WORK IN PROGRESS*

### Functions and Macros

*WORK IN PROGRESS*

## Reference Information

### Existing Kernel Generated Audit Records

The following is a complete list of the existing kernel generated audit record
formats at the time of writing (see the "LAST UPDATED" date at the top of this
file).  This will be helpful in ensuring the existing kernel/userspace ABI is
preserved across the phase one changes.  It is important to note that some
audit record types are not used in modern Linux Kernels, they have been
deprecated and are no longer generated; these types have been omitted from the
list below.

Whenever possible the example audit records below have been taken from live
Linux systems with audit enabled.

#### ANOM_ABEND
```
type=ANOM_ABEND msg=audit(1651071659.310:2184): auid=0 uid=0 gid=0 ses=5
  subj=unconfined_u:unconfined_r:test_inherit_nouse_t:s0-s0:c0.c1023
  pid=4545 comm="child"
  exe="/root/sources/selinux-testsuite/tests/inherit/child" sig=11 res=1
```

#### ANOM_CREAT
```
*MISSING*
```

#### ANOM_LINK
```
*MISSING*
```

#### ANOM_PROMISCUOUS
```
*MISSING*
```

#### AVC
```
type=AVC msg=audit(1650911557.768:4332): avc: denied { accept } for pid=13802
  comm="server"
  scontext=unconfined_u:unconfined_r:test_vsock_server_noaccept_t:s0-s0:c0.c1023
  tcontext=unconfined_u:unconfined_r:test_vsock_server_noaccept_t:s0-s0:c0.c1023
  tclass=vsock_socket permissive=0
```

#### BPF
```
type=BPF msg=audit(1650921443.448:267): prog-id=96 op=LOAD
```

#### BPRM_FCAPS
```
*MISSING*
```

#### CAPSET
```
*MISSING*
```

#### CONFIG_CHANGE
```
type=CONFIG_CHANGE msg=audit(1650909936.993:256711):
  op=set audit_pid=250624 old=0 auid=4294967295 ses=4294967295
  subj=system_u:system_r:auditd_t:s0 res=1
```

#### CRED_ACQ
```
type=CRED_ACQ msg=audit(1650921443.557:282): pid=944 uid=0 auid=0 ses=1
  subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
  msg='op=PAM:setcred grantors=pam_env,pam_localuser,pam_unix acct="root"
  exe="/usr/sbin/sshd" hostname=192.168.3.194 addr=192.168.3.194
  terminal=ssh res=success'
```

#### CRYPTO_KEY_USER
```
type=CRYPTO_KEY_USER msg=audit(1650921443.556:281): pid=944 uid=0 auid=0 ses=1
  subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
  msg='op=destroy kind=server
    fp=SHA256:a1:cd:1c:4b:9b:ff:31:98:b9:02:5f:65:07:85:30:99:45:e7:72:9b:fb:18:7d:46:52:f3:5c:f3:0f:32:ce:92
    direction=? spid=944 suid=0 exe="/usr/sbin/sshd" hostname=? addr=?
    terminal=? res=success'
```

#### CRYPTO_SESSION
```
type=CRYPTO_SESSION msg=audit(1650921443.278:235): pid=932 uid=0 auid=4294967295
  ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
  msg='op=start direction=from-server cipher=chacha20-poly1305@openssh.com
    ksize=512 mac=<implicit> pfs=curve25519-sha256 spid=933 suid=74 rport=51930
    laddr=192.168.0.84 lport=22  exe="/usr/sbin/sshd" hostname=?
    addr=192.168.3.194 terminal=? res=success'
```

#### CWD
```
type=CWD msg=audit(1651071579.768:2004):
  cwd="/root/sources/audit-testsuite/tests"
```

#### DM_CTRL
```
*MISSING*
```

#### DM_EVENT
```
*MISSING*
```

#### EVENT_LISTENER
```
*MISSING*
```

#### EXECVE
```
type=EXECVE msg=audit(1651071568.955:783): argc=3
  a0="auditctl" a1="-m" a2="syncmarker-testsuite-1651071568-ZgLjCJrf"
```

#### FANOTIFY
```
type=FANOTIFY msg=audit(1651071584.370:2160): resp=1
```

#### FD_PAIR
```
*MISSING*
```

#### FEATURE_CHANGE
```
*MISSING*
```

#### INTEGRITY_DATA
```
*MISSING*
```

#### INTEGRITY_EVM_XATTR
```
*MISSING*
```

#### INTEGRITY_METADATA
```
*MISSING*
```

#### INTEGRITY_PCR
```
*MISSING*
```

#### INTEGRITY_POLICY_RULE
```
*MISSING*
```

#### INTEGRITY_RULE
```
*MISSING*
```

#### INTEGRITY_STATUS
```
*MISSING*
```

#### IPC
```
*MISSING*
```

#### IPC_SET_PERM
```
*MISSING*
```

#### KERN_MODULE
```
type=KERN_MODULE msg=audit(1651071579.835:2028): name="arp_tables"
```

#### MAC_CALIPSO_ADD
```
type=MAC_CALIPSO_ADD msg=audit(1651071698.472:2475): netlabel: auid=0 ses=5
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  calipso_doi=16 calipso_type=pass res=1
```

#### MAC_CALIPSO_DEL
```
type=MAC_CALIPSO_DEL msg=audit(1651071703.601:2484): netlabel: auid=0 ses=5
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  calipso_doi=16 res=1
```

#### MAC_CIPSOV4_ADD
```
type=MAC_CIPSOV4_ADD msg=audit(1651071667.333:2363): netlabel: auid=0 ses=5
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  cipso_doi=1 cipso_type=local res=1
```

#### MAC_CIPSOV4_DEL
```
type=MAC_CIPSOV4_DEL msg=audit(1651071668.414:2372): netlabel: auid=0 ses=5
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 cipso_doi=1 res=1
```

#### MAC_CONFIG_CHANGE
```
type=MAC_CONFIG_CHANGE msg=audit(1651071645.183:2171): bool=domain_fd_use
  val=0 old_val=1 auid=0 ses=5
```

#### MAC_IPSEC_EVENT
```
type=MAC_IPSEC_EVENT msg=audit(1651071671.725:2412): op=SAD-add auid=0 ses=5
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  sec_alg=1 sec_doi=1
  sec_obj=unconfined_u:unconfined_r:test_inet_client_t:s0-s0:c0.c1023
  src=127.0.0.1 dst=127.0.0.1 spi=512(0x200) res=1
```

#### MAC_MAP_ADD
```
type=MAC_MAP_ADD msg=audit(1651071771.070:2649): netlabel: auid=0 ses=5
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  nlbl_domain=(default) dst=127.0.0.1 nlbl_protocol=cipsov4 cipso_doi=1 res=1
```

#### MAC_MAP_DEL
```
type=MAC_MAP_DEL msg=audit(1651071779.185:2654): netlabel: auid=0 ses=5
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  nlbl_domain=(default) res=1
```

#### MAC_POLICY_LOAD
```
type=MAC_POLICY_LOAD msg=audit(1651071656.033:2172): auid=0 ses=5
  lsm=selinux res=1
```

#### MAC_STATUS
```
type=MAC_STATUS msg=audit(1651071561.178:507):
  enforcing=1 old_enforcing=0 auid=0 ses=5 enabled=1 old-enabled=1
  lsm=selinux res=1
```

#### MAC_UNLBL_ALLOW
```
*MISSING*
```

#### MAC_UNLBL_STCADD
```
type=MAC_UNLBL_STCADD msg=audit(1651071710.268:2578): netlabel: auid=0 ses=5
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  netif=lo src=0000:0000:0000:0000:0000:0000:0000:0001
  sec_obj=system_u:object_r:netlabel_sctp_peer_t:s0 res=1
```

#### MAC_UNLBL_STCDEL
```
type=MAC_UNLBL_STCDEL msg=audit(1651071730.484:2590): netlabel: auid=0 ses=5
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  netif=lo src=127.0.0.0 src_prefixlen=8
  sec_obj=system_u:object_r:netlabel_sctp_peer_t:s0 res=1
```

#### MMAP
```
*MISSING*
```

#### MQ_OPEN
```
*MISSING*
```

#### MQ_SENDRECV
```
*MISSING*
```

#### MQ_NOTIFY
```
*MISSING*
```

#### MQ_GETSETATTR
```
*MISSING*
```

#### NETFILTER_PKT
```
type=NETFILTER_PKT msg=audit(1651071576.281:1029):
  mark=0xdbe479fc saddr=127.0.0.1 daddr=127.0.0.1 proto=1
```

#### NETFILTER_CFG
```
type=NETFILTER_CFG msg=audit(1651071696.419:2469):
  table=security:48 family=10 entries=14 op=nft_register_obj pid=5376
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 comm="nft"
```

#### OBJ_PID
```
type=OBJ_PID msg=audit(1651071577.411:1056): opid=3133 oauid=0 ouid=0 oses=5
  obj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 ocomm="perl"
```

#### OPENAT2
```
type=OPENAT2 msg=audit(1651071579.698:1183): oflag=0302 mode=0600 resolve=0xa
```

#### PATH
```
type=PATH msg=audit(1650909891.172:256581):
  item=1 name="/lib64/ld-linux-x86-64.so.2" inode=4981640 dev=fc:04
  mode=0100755 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:ld_so_t:s0
  nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
```

#### PROCTITLE
```
type=PROCTITLE msg=audit(1650921443.448:265):
  proctitle=2F7573722F6C69622F73797374656D642F73797374656D64002D2D75736572
```

#### REPLACE
```
*MISSING*
```

#### SECCOMP
```
*MISSING*
```

#### SELINUX_ERR
```
type=SELINUX_ERR msg=audit(1651071666.620:2301):
  op=security_bounded_transition seresult=denied
  oldcontext=unconfined_u:unconfined_r:test_bounds_parent_t:s0-s0:c0.c1023
  newcontext=unconfined_u:unconfined_r:test_bounds_unbound_t:s0-s0:c0.c1023
```

#### SERVICE_START
```
type=SERVICE_START
  msg=audit(1650921443.544:279): pid=1 uid=0 auid=4294967295 ses=4294967295
  subj=system_u:system_r:init_t:s0
  msg='unit=user@0 comm="systemd" exe="/usr/lib/systemd/systemd"
    hostname=? addr=? terminal=? res=success'
```

#### SERVICE_STOP
```
type=SERVICE_STOP msg=audit(1650921473.724:289): pid=1 uid=0 auid=4294967295
  ses=4294967295 subj=system_u:system_r:init_t:s0
  msg='unit=systemd-hostnamed comm="systemd" exe="/usr/lib/systemd/systemd"
    hostname=? addr=? terminal=? res=success'
```

#### SOCKADDR
```
type=SOCKADDR msg=audit(1651071571.962:942):
  saddr=020000007F0000010000000000000000
```

#### SOCKETCALL
```
type=SOCKETCALL msg=audit(1651071580.018:2035): nargs=3 a0=3 a1=fff900f0 a2=10
```

#### SYSCALL
```
type=SYSCALL msg=audit(1650921443.448:267):
  arch=c000003e syscall=321 success=yes exit=8
  a0=5 a1=7ffefc8fa680 a2=90 a3=2 items=0 ppid=1 pid=935
  auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0
  tty=(none) ses=2 comm="systemd" exe="/usr/lib/systemd/systemd"
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  key=(null)
```

#### TIME_INJOFFSET
```
type=TIME_INJOFFSET msg=audit(757094400.123:2040): sec=893977180 nsec=8797028
```

#### TIME_ADJNTPVAL
```
type=TIME_ADJNTPVAL msg=audit(1651071580.629:2088): op=status old=1 new=64
```

#### TTY
```
*MISSING*
```

#### URINGOP
```
*MISSING*
```

#### USER
```
type=USER msg=audit(1650909892.518:256707): pid=250501 uid=0 auid=0 ses=1
  subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  msg='text=syncmarker-testsuite-1650909892-mGuSxzfn exe="/usr/sbin/auditctl"
    hostname=dev-rawhide-1.lan addr=? terminal=pts/0 res=success'
```

#### USER_ACCT
```
type=USER_ACCT msg=audit(1650921443.340:240): pid=932 uid=0 auid=4294967295
  ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
  msg='op=PAM:accounting grantors=pam_unix,pam_localuser acct="root"
    exe="/usr/sbin/sshd" hostname=192.168.3.194 addr=192.168.3.194 terminal=ssh
    res=success'
```

#### USER_AUTH
```
type=USER_AUTH msg=audit(1650921443.314:237): pid=932 uid=0 auid=4294967295
  ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
  msg='op=pubkey acct="root" exe="/usr/sbin/sshd" hostname=? addr=192.168.3.194
    terminal=ssh res=failed'
```

#### USER_AVC
```
*MISSING*
```

#### USER_LOGIN
```
type=USER_LOGIN msg=audit(1650921443.612:283): pid=932 uid=0 auid=0 ses=1
  subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
  msg='op=login id=0 exe="/usr/sbin/sshd" hostname=? addr=192.168.3.194
  terminal=/dev/pts/0 res=success'
```

#### USER_LOGOUT
```
type=USER_LOGOUT msg=audit(1650910076.017:256718): pid=847 uid=0 auid=0 ses=1
  subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=0
  exe="/usr/sbin/sshd" hostname=? addr=? terminal=/dev/pts/0 res=success'
```

#### USER_END
```
type=USER_END msg=audit(1650910076.015:256713): pid=3195 uid=0 auid=0 ses=4
  subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
  msg='op=PAM:session_close grantors=pam_selinux,pam_loginuid,pam_selinux,pam_namespace,pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix,pam_umask,pam_lastlog
    acct="root" exe="/usr/sbin/sshd" hostname=192.168.3.194 addr=192.168.3.194
    terminal=ssh res=success'
```

#### USER_ROLE_CHANGE
```
type=USER_ROLE_CHANGE msg=audit(1650921443.345:244): pid=932 uid=0 auid=0 ses=1
  subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
  msg='pam:
    default-context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
    selected-context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
    exe="/usr/sbin/sshd" hostname=192.168.3.194 addr=192.168.3.194 terminal=ssh
    res=success'
```

#### USER_START
```
type=USER_START msg=audit(1650921443.554:280): pid=932 uid=0 auid=0 ses=1
  subj=system_u:system_r:sshd_t:s0-s0:c0.c1023
  msg='op=PAM:session_open
    grantors=pam_selinux,pam_loginuid,pam_selinux,pam_namespace,pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix,pam_umask,pam_lastlog
    acct="root" exe="/usr/sbin/sshd" hostname=192.168.3.194 addr=192.168.3.194
    terminal=ssh res=success'
```

#### USER_TTY
```
*MISSING*
```
