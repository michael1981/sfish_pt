
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40011);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  kernel (2009-01-14)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for kernel");
 script_set_attribute(attribute: "description", value: "This update fixes various security issues and several bugs
in the openSUSE 11.0 kernel. It was also updated to the
stable version 2.6.25.20.

CVE-2008-5702: Buffer underflow in the ibwdt_ioctl function
in drivers/watchdog/ib700wdt.c might allow local users to
have an unknown impact via a certain /dev/watchdog
WDIOC_SETTIMEOUT IOCTL call.

CVE-2008-5700: libata did not set minimum timeouts for
SG_IO requests, which allows local users to cause a denial
of service (Programmed I/O mode on drives) via multiple
simultaneous invocations of an unspecified test program.

CVE-2008-5079: net/atm/svc.c in the ATM subsystem allowed
local users to cause a denial of service (kernel infinite
loop) by making two calls to svc_listen for the same
socket, and then reading a /proc/net/atm/*vc file, related
to corruption of the vcc table.

CVE-2008-5300: Linux kernel 2.6.28 allows local users to
cause a denial of service ('soft lockup' and process loss)
via a large number of sendmsg function calls, which does
not block during AF_UNIX garbage collection and triggers an
OOM condition, a different vulnerability than CVE-2008-5029.

CVE-2008-5029: The __scm_destroy function in net/core/scm.c
makes indirect recursive calls to itself through calls to
the fput function, which allows local users to cause a
denial of service (panic) via vectors related to sending an
SCM_RIGHTS message through a UNIX domain socket and closing
file descriptors.

CVE-2008-4933: Buffer overflow in the hfsplus_find_cat
function in fs/hfsplus/catalog.c allowed attackers to cause
a denial of service (memory corruption or system crash) via
an hfsplus filesystem image with an invalid catalog
namelength field, related to the hfsplus_cat_build_key_uni
function.

CVE-2008-5025: Stack-based buffer overflow in the
hfs_cat_find_brec function in fs/hfs/catalog.c allowed
attackers to cause a denial of service (memory corruption
or system crash) via an hfs filesystem image with an
invalid catalog namelength field, a related issue to
CVE-2008-4933.

CVE-2008-5182: The inotify functionality might allow local
users to gain privileges via unknown vectors related to
race conditions in inotify watch removal and umount.

CVE-2008-3831: The i915 driver in
drivers/char/drm/i915_dma.c does not restrict the
DRM_I915_HWS_ADDR ioctl to the Direct Rendering Manager
(DRM) master, which allows local users to cause a denial of
service (memory corruption) via a crafted ioctl call,
related to absence of the DRM_MASTER and DRM_ROOT_ONLY
flags in the ioctl's configuration.

CVE-2008-4554: The do_splice_from function in fs/splice.c
did not reject file descriptors that have the O_APPEND flag
set, which allows local users to bypass append mode and
make arbitrary changes to other locations in the file.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for kernel");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=447406");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=399966");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=457898");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=457897");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=457896");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=419250");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=405546");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=450417");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=442364");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=447241");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=439461");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=442594");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=443640");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=446973");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=445569");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=443661");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=362850");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=439461");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=371657");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=429919");
script_end_attributes();

 script_cve_id("CVE-2008-3831", "CVE-2008-4554", "CVE-2008-4933", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5079", "CVE-2008-5182", "CVE-2008-5300", "CVE-2008-5700", "CVE-2008-5702");
script_summary(english: "Check for the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-debug-2.6.25.20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.25.20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.25.20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.25.20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-docs-2.6.25.20-0.1", release:"SUSE11.0", cpu:"noarch") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-pae-2.6.25.20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt-2.6.25.20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt-2.6.25.20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt_debug-2.6.25.20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-rt_debug-2.6.25.20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.25.20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.25.20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.25.20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.25.20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-2.6.25.20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-vanilla-2.6.25.20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.25.20-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.25.20-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
