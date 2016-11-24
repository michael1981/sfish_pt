
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
 script_id(30250);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Linux Kernel update (kernel-4970)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-4970");
 script_set_attribute(attribute: "description", value: "This kernel update is a respin of a previous one that broke
CPUFREQ support (bug 357598).

Previous changes:

This kernel update fixes the following security problems:

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

CVE-2007-3843: The Linux kernel checked the wrong global
variable for the CIFS sec mount option, which might allow
remote attackers to spoof CIFS network traffic that the
client configured for security signatures, as demonstrated
by lack of signing despite sec=ntlmv2i in a SetupAndX
request.

CVE-2007-6417: The shmem_getpage function (mm/shmem.c) in
Linux kernel 2.6.11 through 2.6.23 does not properly clear
allocated memory in some rare circumstances, which might
allow local users to read sensitive kernel data or cause a
denial of service (crash).

And the following bugs (numbers are
https://bugzilla.novell.com/ references):

- patches.fixes/input-add-amilo-pro-v-to-nomux.patch: Add
  Fujitsu-Siemens Amilo Pro 2010 to nomux list (345699).
- patches.arch/acpica-psd.patch: Changed resolution of
  named references in packages
  (https://bugzilla.novell.com/show_bug.cgi?id=346831).
- patches.fixes/acpica_sizeof.patch: SizeOf operator ACPI
  interpreter fix
  (http://bugzilla.kernel.org/show_bug.cgi?id=9558).
- patches.drivers/libata-sata_sis-fix-scr-access: sata_sis:
  fix SCR access (331610).
- patches.drivers/libata-tape-fix: libata: backport tape
  support fixes (345438).
- patches.arch/powernowk8_family_freq_from_fiddid.patch: To
  find the frequency given the fid and did is family
  dependant. (#332722).
- patches.drivers/libata-force-cable-type: libata:
  implement libata.force_cbl parameter (337610).
- patches.drivers/libata-sata_nv-disable-ADMA: sata_nv:
  disable ADMA by default (346508).
- patches.fixes/via-velocity-dont-oops-on-mtu-change-1:
  [VIA_VELOCITY]: Don't oops on MTU change. (341537).
- patches.fixes/via-velocity-dont-oops-on-mtu-change-2:
  via-velocity: don't oops on MTU change while down
  (341537).
-
patches.fixes/sony-laptop-call-sonypi_compat_init-earlier: s
  ony-laptop: call sonypi_compat_init earlier (343483).
- Updated kABI symbols for 2.6.22.15 changes, and Xen
  x86_64 changes.
- series.conf file cleanup: group together latency tracing
  patches.
- Fix a memory leak and a panic in drivers/block/cciss.c
  patches.drivers/cciss-panic-in-blk_rq_map_sg: Panic in
  blk_rq_map_sg() from CCISS driver.
- patches.drivers/cciss-fix_memory_leak:
- Address missed-interrupt issues discovered upstream.
- Update to 2.6.22.15
  - fixes CVE-2007-5966
  - lots of libata fixes, which cause the following to be
    removed:
     -
patches.drivers/libata-add-NCQ-spurious-completion-horkages
     -
patches.drivers/libata-add-ST9120822AS-to-NCQ-blacklist
     -
patches.drivers/libata-disable-NCQ-for-ST9160821AS-3.ALD
  - removed patches already in this release:
     -
patches.fixes/i4l-avoid-copying-an-overly-long-string.patch:
     - patches.fixes/ramdisk-2.6.23-corruption_fix.diff
     - patches.fixes/microtek_hal.diff: Delete.
  - fixed previous poweroff regression from 2.6.22.10
  - lots of other fixes and some new pci ids.
- Thousands of changes in patches.rt/ for the kernel-rt*
  kernels.
- patches.fixes/usb_336850.diff: fix missing quirk leading
  to a device disconnecting under load (336850).
- patches.fixes/nfs-unmount-leak.patch: NFSv2/v3: Fix a
  memory leak when using -onolock (336253).
- add xenfb-module-param patch to make Xen virtual frame
  buffer configurable in the guest domains, instead of a
  fixed resolution of 800x600.
- patches.xen/xen3-aux-at_vector_size.patch:  Also include
  x86-64 (310037).
- patches.xen/xen3-patch-2.6.18: Fix system lockup (335121).
- patches.fixes/acpi_autoload_baydock.patch: autloading of
  dock module (302482). Fixed a general bug with linux
  specific hids there.
- patches.xen/xen3-patch-2.6.22.11-12: Linux 2.6.22.12.
- patches.xen/xen3-fixup-arch-i386: Fix CONFIG_APM=m issue.
- patches.xen/xen-x86-no-lapic: Re-diff.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-4970");
script_end_attributes();

script_cve_id("CVE-2008-0007", "CVE-2008-0001", "CVE-2007-5966", "CVE-2007-3843", "CVE-2007-6417", "CVE-2007-5966");
script_summary(english: "Check for the kernel-4970 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-rt-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-rt_debug-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.22.16-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
