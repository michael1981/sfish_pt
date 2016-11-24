
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
 script_id(29488);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-4471)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-4471");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- - CVE-2007-4573: It was possible for local user to become
  root by exploiting a bug in the IA32 system call
  emulation. This affects x86_64 platforms with kernel
  2.4.x and 2.6.x before 2.6.22.7 only.

- - CVE-2007-4571: An information disclosure vulnerability
  in the ALSA driver can be exploited by local users to
  read sensitive data from the kernel memory.

and the following non security bugs:

- -  patches.xen/xen-blkback-cdrom: CDROM removable
  media-present attribute plus handling code   [#159907]
- -  patches.drivers/libata-add-pata_dma-kernel-parameter:
  libata: Add a drivers/ide style  DMA disable  [#229260]
  [#272786]
- -
  patches.drivers/libata-sata_via-kill-SATA_PATA_SHARING:
  sata_via: kill SATA_PATA_SHARING register handling
  [#254158] [#309069]
- -  patches.drivers/libata-sata_via-add-PCI-IDs:
  sata_via: add PCI IDs  [#254158] [#326647]
- -  supported.conf: Marked 8250 and 8250_pci as supported
  (only Xen kernels build them as modules) [#260686]
- -  patches.fixes/bridge-module-get-put.patch: Module use
  count must be updated as bridges are created/destroyed
  [#267651]
- -  patches.fixes/iscsi-netware-fix: Linux Initiator hard
  hangs writing files to NetWare target  [#286566] 
- -  patches.fixes/lockd-chroot-fix: Allow lockd to work
  reliably with applications in a chroot [#288376] [#305480]
- -  add patches.fixes/x86_64-hangcheck_timer-fix.patch fix
  monotonic_clock() and hangcheck_timer [#291633]
- -  patches.arch/sn_hwperf_cpuinfo_fix.diff: Correctly
  count CPU objects for SGI ia64/sn hwperf interface
  [#292240]
- -  Extend reiserfs to properly support file systems up to
  16 TiB  [#294754]
     - patches.fixes/reiserfs-signedness-fixes.diff:
reiserfs: fix usage of signed ints for block numbers
     - patches.fixes/reiserfs-fix-large-fs.diff:  reiserfs:
ignore s_bmap_nr on disk for file systems >= 8 TiB 
- -  patches.suse/ocfs2-06-per-resource-events.diff:
  Deliver events without a specified resource
  unconditionally.  [#296606]
- -  patches.fixes/proc-readdir-race-fix.patch:  Fix the
  race in proc_pid_readdir  [#297232]
- -  patches.xen/xen3-patch-2.6.16.49-50: XEN: update to
  Linux 2.6.16.50 [#298719]
- -  patches.fixes/pm-ordering-fix.patch: PM: Fix ACPI
  suspend / device suspend ordering  [#302207]
- -  patches.drivers/ibmvscsi-slave_configure.patch add
  ->slave_configure() to allow device restart  [#304138]
- -  patches.arch/ppc-power6-ebus-unique_location.patch
  Prevent bus_id collisions  [#306482]
- -  patches.xen/30-bit-field-booleans.patch: Fix packet
  loss in DomU xen netback driver  [#306896]
- -  config/i386/kdump: Enable ahci module  [#308556]
- -  update patches.drivers/ppc-power6-ehea.patch fix link
  state detection for bonding  [#309553]
- -  patches.drivers/ibmveth-fixup-pool_deactivate.patch
  patches.drivers/ibmveth-large-frames.patch
  patches.drivers/ibmveth-large-mtu.patch: fix serveral
  crashes when changing ibmveth sysfs values  [#326164]
- -
patches.drivers/libata-sata_sil24-fix-IRQ-clearing-race-on-I
  RQ_WOC: sata_sil24: fix IRQ clearing race when
  PCIX_IRQ_WOC is used [#327536]
- -  update patches.drivers/ibmvscsis.patch set blocksize
  to PAGE_CACHE_SIZE to fix flood of bio allocation
  warnings/failures [#328219]


Fixes for S/390:

- - IBM Patchcluster 17  [#330036]

    - Problem-ID:  38085 - zfcp: zfcp_scsi_eh_abort_handler
or zfcp_scsi_eh_device_reset_handler hanging after CHPID
off/on
    - Problem-ID:  38491 - zfcp: Error messages when LUN 0
is present
    - Problem-ID:  37390 - zcrypt: fix PCIXCC/CEX2C error
recovery [#306056]
    - Problem-ID:  38500 - kernel: too few page cache pages
in state volatile
    - Problem-ID:  38634 - qeth: crash during reboot after
failing online setting
    - Problem-ID:  38927 - kernel: shared memory may not be
volatile
    - Problem-ID:  39069 - cio: Disable channel path
measurements on shutdown/reboot
    - Problem-ID:  27787 - qeth: recognize 'exclusively
used'-RC from Hydra3
    - Problem-ID:  38330 - qeth: make qeth driver loadable
without ipv6 module


    For further description of the named Problem-IDs,
please look to
http://www-128.ibm.com/developerworks/linux/linux390/october
2005_recommended.html
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-4471");
script_end_attributes();

script_cve_id("CVE-2007-4571", "CVE-2007-4573");
script_summary(english: "Check for the kernel-4471 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.53-0.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.53-0.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.53-0.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.53-0.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.53-0.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.53-0.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.53-0.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.53-0.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.53-0.16", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.53-0.16", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.53-0.16", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.53-0.16", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.53-0.16", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.53-0.16", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.53-0.16", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.53-0.16", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
