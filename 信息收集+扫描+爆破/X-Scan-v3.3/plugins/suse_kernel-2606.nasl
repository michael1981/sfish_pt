
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(29486);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-2606)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-2606");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- CVE-2006-2936: The ftdi_sio driver allowed local users to
  cause a denial of service (memory consumption) by writing
  more data to the serial port than the hardware can
  handle, which causes the data to be queued. This requires
  this driver to be  loaded, which only happens if such a
  device is plugged in. 

- CVE-2006-4814: A deadlock in mincore that could be caused
  by local  attackers was fixed. 

- CVE-2006-6106: Multiple buffer overflows in the
  cmtp_recv_interopmsg function in the Bluetooth driver
  (net/bluetooth/cmtp/capi.c) in the Linux kernel allowed
  remote attackers to cause a denial of service (crash) and
  possibly execute arbitrary code via CAPI messages with a
  large value for the length of the (1) manu (manufacturer)
  or (2) serial (serial number) field. 

- CVE-2006-5749: The isdn_ppp_ccp_reset_alloc_state
  function in drivers/isdn/isdn_ppp.c in the Linux kernel
  does not call the init_timer function for the ISDN PPP
  CCP reset state timer, which has unknown attack vectors
  and results in a system crash. 

- CVE-2006-5753: Unspecified vulnerability in the listxattr
  system call in Linux kernel, when a 'bad inode' is
  present, allows local users to cause a denial of service
  (data corruption) and possibly gain privileges.

-                A remote denial of service problem on
NFSv2 mounts with ACL enabled was fixed. 


and the following non security bugs:

- patches.xen/xen-x86_64-agp: add missing header [#222174]
  [#224170]
- patches.fixes/dcache-race-during-umount: Fix dcache race
  during umount  [#136310] [#151638]
- patches.arch/x86_64-kdump-bootmem-fix: Handle
  reserve_bootmem_generic beyond end_pfn  [#179093]
- patches.fixes/rpc-no-paranoia:  Ratelimit some messages
  from SUNRPC servers (nfsd)  [#190178]
- patches.fixes/nfs-lock-warning-removal: Remove useless
  warning about VFS being out of sync with lock manager
  [#192813]
- patches.fixes/acpiphp-fix-ibm-hotplug-oops.patch: Fix
  acpiphp oops when hotplug is performed on an IBM 8864/6
  [#203923]
- patches.fixes/oom-child-kill-fix.patch: OOM: prevent
  OOM_DISABLE tasks from being killed when out of memory
  [#211859]
- patches.drivers/alsa-control-warning-fix: Fix bogus
  kernel error messages from ALSA control.c  [#212484]
- patches.fixes/init_isolcpus.diff:  sched: force
  /sbin/init off isolated cpus  [#216799]
- patches.fixes/ocfs2-network-send-lock.diff: fix
  regression that caused the idle timer not to be reset
  during packet processing  [#216912]
- patches.fixes/workqueue_cpu_deadlock-fix.diff:  [PATCH]
  workqueue: fix deadlock when workqueue func takes the
  workqueue mutex   [#217222]
- patches.drivers/open-iscsi-handle-check-condition: Host
  lockups then Reboots when an iSCSI session is attempted
  [#219968]
- patches.arch/ia64-fp-rate-limit: [ia64] Reduce overhead
  of FP exception logging messages.  [#223314]
- patches.arch/ia64-sn2-bte_unaligned_copy-overrun: [ia64]
  Avert transfer of extra cache line by
  bte_unaligned_copy(). [#224166]
- patches.fixes/natsemi-long-cable-fix:  natsemi: make
  cable length magic configurable  [#225091]
- patches.fixes/sunrpc-randomize-xids: SUNRPC: NFS_ROOT
  always uses the same XIDs  [#225251]
- patches.drivers/usb-funsoft-hwinfo.patch: USB: fix hwinfo
  issue with funsoft driver  [#226661]
patches.fixes/fix-ext3-kmalloc-flags-with-journal-handle.diff: ext3: use GFP_NOFS for allocations while holding journal handle [#228694]
- patches.fixes/nfs-tcp-reconnect-on-error: RPC: Ensure
  that we disconnect TCP socket when client requests error
  out  [#230210]
- patches.fixes/sunrpc-listen-race: knfsd: Fix race that
  can disable NFS server.  [#230287]
patches.drivers/pci-quirk-1k-i-o-space-iobl_adr-fix-on-p64h2.patch: PCI Quirk: 1k I/O space IOBL_ADR fix on P64H2  [#230365]
- patches.drivers/ide-generic-fix-JMB-entries: [PATCH]
  ide-generic: fix JMB handling  [#231218] [#207939]
- patches.drivers/qla2xxx-block-error-handler: crash in
  qla2xxx driver during error recovery  [#232957]
- patches.fixes/loop_early_wakeup_fix.diff: Fix oops in
  loopback device during mount.  [#232992]
- patches.fixes/nfs-jiffie-wrap: Avoid extra GETATTR calls
  caused by 'jiffie wrap'.  [#233155]
- add patches.fixes/atalk_sendmsg-crash.patch Fix potential
  OOPS in atalk_sendmsg()  [#235049]
- patches.fixes/ext3_readdir_use_generic_readahead.diff:
  ext3_readdir: use generic readahead  [#228682] [#235302]
- patches.drivers/ide-fix-drive-side-80c-detection: [PATCH]
  ide: fix drive side 80c cable detection  [#237164]
- patches.fixes/xfs-kern-28000a-buffer-unwritten-new: Set
  the buffer new flag on writes to unwritten XFS extents.
  This fixes a corruption in preallocated files on XFS
  [#237908]
- patches.drivers/ide-atiixp-fix-cable-detection: [PATCH]
  atiixp: fix cable detection  [#241403]
- patches.drivers/ide-atiixp-sb600-has-only-one-port:
  [PATCH] atiixp: SB600 has only one channel  [#241403]
- patches.fixes/md-avoid-bitmap-overflow: Avoid possible
  BUG_ON in md bitmap handling.  [#242180]
- patches.fixes/ocfs2-loop-aops-hack.diff: ocfs2/loop:
  forbid use of aops when inappropriate  [#242200]
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-2606");
script_end_attributes();

script_cve_id("CVE-2006-2936", "CVE-2006-4814", "CVE-2006-5749", "CVE-2006-5753", "CVE-2006-6106");
script_summary(english: "Check for the kernel-2606 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.27-0.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.27-0.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.27-0.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.27-0.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.27-0.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.27-0.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.27-0.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.27-0.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.27-0.9", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.27-0.9", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.27-0.9", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.27-0.9", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.27-0.9", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.27-0.9", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
