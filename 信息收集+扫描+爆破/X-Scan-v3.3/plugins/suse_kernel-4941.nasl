
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
 script_id(30143);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Kernel Update for SUSE Linux 10.1 (kernel-4941)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-4941");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems: 

CVE-2008-0007: Insufficient range checks in certain fault
handlers could be used by local attackers to potentially
read or write kernel memory.

CVE-2008-0001: Incorrect access mode checks could be used
by local attackers to corrupt directory contents and so
cause denial of service attacks or potentially execute code.

CVE-2007-5966: Integer overflow in the hrtimer_start
function in kernel/hrtimer.c in the Linux kernel before
2.6.23.10 allows local users to execute arbitrary code or
cause a denial of service (panic) via a large relative
timeout value. NOTE: some of these details are obtained
from third party information.

CVE-2007-6417: The shmem_getpage function (mm/shmem.c) in
Linux kernel 2.6.11 through 2.6.23 does not properly clear
allocated memory in some rare circumstances, which might
allow local users to read sensitive kernel data or cause a
denial of service (crash).


Furthermore, this kernel catches up to the SLE 10 state of
the kernel, with massive additional fixes.

All platforms:
- patches.suse/bootsplash: Bootsplash for current kernel
  (none). patch the patch for Bug number 345980.
- patches.fixes/megaraid-fixup-driver-version: Megaraid
  driver version out of sync (299740).

- OCFS2: Updated to version 1.2.8

- patches.fixes/ocfs2-1.2-svn-r3070.diff: [PATCH] ocfs2:
  Remove overzealous BUG_ON().
- patches.fixes/ocfs2-1.2-svn-r3072.diff: [PATCH] ocfs2:
  fix rename vs unlink race.
- patches.fixes/ocfs2-1.2-svn-r3074.diff: [PATCH] ocfs2:
  Remove expensive local alloc bitmap scan code.
- patches.fixes/ocfs2-1.2-svn-r3057.diff: [PATCH] ocfs2:
  Check for cluster locking in ocfs2_readpage.
- patches.fixes/ocfs2-1.2-svn-r2975.diff: ocfs2_dlm: make
  functions static.
- patches.fixes/ocfs2-1.2-svn-r2976.diff: [PATCH]
  ocfs2_dlm: make tot_backoff more descriptive.
- patches.fixes/ocfs2-1.2-svn-r3002.diff: [PATCH] ocfs2:
  Remove the printing of harmless ERRORS like ECONNRESET,
  EPIPE..
- patches.fixes/ocfs2-1.2-svn-r3004.diff: [PATCH]
  ocfs2_dlm: Call cond_resched_lock() once per hash bucket
  scan.
- patches.fixes/ocfs2-1.2-svn-r3006.diff: [PATCH]
  ocfs2_dlm: Silence compiler warnings.
- patches.fixes/ocfs2-1.2-svn-r3062.diff: [PATCH]
  ocfs2_dlm: Fix double increment of migrated lockres'
  owner count.

- patches.fixes/hugetlb-get_user_pages-corruption.patch:
  hugetlb: follow_hugetlb_page() for write access (345239).

- enable patches.fixes/reiserfs-fault-in-pages.patch
  (333412)

- patches.drivers/usb-update-evdo-driver-ids.patch: USB:
  update evdo driver ids. Get the module to build...

-
patches.drivers/usb-add-usb_device_and_interface_info.patch:
   USB: add USB_DEVICE_AND_INTERFACE_INFO().  This is
  needed to get the HUAWEI devices to work properly, and to
  get patches.drivers/usb-update-evdo-driver-ids.patch to
  build without errors.

- patches.drivers/usb-update-evdo-driver-ids.patch: USB:
  update evdo driver ids on request from our IT department
  (345438).

- patches.suse/kdump-dump_after_notifier.patch: Add
  dump_after_notifier sysctl (265764).

- patches.drivers/libata-sata_nv-disable-ADMA: sata_nv:
  disable ADMA by default (346508).

- patches.fixes/cpufreq-fix-ondemand-deadlock.patch:
  Cpufreq fix ondemand deadlock (337439).
-
patches.fixes/eliminate-cpufreq_userspace-scaling_setspeed-d
  eadlock.patch: Eliminate cpufreq_userspace
  scaling_setspeed deadlock (337439).

- patches.xen/15181-dma-tracking.patch: Fix issue
  preventing Xen KMPs from building.

- patches.drivers/r8169-perform-a-PHY-reset-before.patch:
  r8169: perform a PHY reset before any other operation at
  boot time (345658).
- patches.drivers/r8169-more-alignment-for-the-0x8168:
  refresh.

- patches.fixes/lockd-grant-shutdown: Stop GRANT callback
  from crashing if NFS server has been stopped. (292478).
  There was a problem with this patch which would cause
  apparently random crashes when lockd was in use.  The
  offending change has been removed.

- patches.fixes/usb_336850.diff: fix missing quirk leading
  to a device disconnecting under load (336850).

- patches.fixes/cifs-incomplete-recv.patch: fix incorrect
  session reconnects (279783).

- patches.fixes/megaraid_mbox-dell-cerc-support: Fix so
  that it applies properly. I extended the context to 6
  lines to help patch find where to apply the patch
  (267134).

- patches.fixes/md-idle-test: md: improve the is_mddev_idle
  test fix (326591).


AMD64/Intel EM64T (x86_64) specific:
- patches.arch/x86_64-mce-loop: x86_64: fix misplaced
  `continue' in mce.c (344239).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-4941");
script_end_attributes();

script_cve_id("CVE-2008-0007", "CVE-2008-0001", "CVE-2007-5966", "CVE-2007-6417");
script_summary(english: "Check for the kernel-4941 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.54-0.2.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kexec-tools-1.101-32.45.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mkinitrd-1.2-106.62.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"multipath-tools-0.4.6-25.23", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"open-iscsi-2.0.707-0.32", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"udev-085-30.44.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
