
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35446);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Linux Kernel update (kernel-5920)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-5920");
 script_set_attribute(attribute: "description", value: "The openSUSE 10.3 kernel was updated to fix various
security problems and bugs. Following security bugs were
fixed:

CVE-2008-5702: Buffer underflow in the ibwdt_ioctl function
in drivers/watchdog/ib700wdt.c might allow local users to
have an unknown impact via a certain /dev/watchdog
WDIOC_SETTIMEOUT IOCTL call.

CVE-2008-5079: net/atm/svc.c in the ATM subsystem allowed
local users to cause a denial of service (kernel infinite
loop) by making two calls to svc_listen for the same
socket, and then reading a /proc/net/atm/*vc file, related
to corruption of the vcc table.

CVE-2008-5029: The __scm_destroy function in net/core/scm.c
makes indirect recursive calls to itself through calls to
the fput function, which allows local users to cause a
denial of service (panic) via vectors related to sending an
SCM_RIGHTS message through a UNIX domain socket and closing
file descriptors.

CVE-2008-5134: Buffer overflow in the lbs_process_bss
function in drivers/net/wireless/libertas/scan.c in the
libertas subsystem allowed remote attackers to have an
unknown impact via an 'invalid beacon/probe response.'

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
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-5920");
script_end_attributes();

script_cve_id("CVE-2008-5702", "CVE-2008-5079", "CVE-2008-5029", "CVE-2008-5134", "CVE-2008-4933", "CVE-2008-5025", "CVE-2008-4933", "CVE-2008-5182");
script_summary(english: "Check for the kernel-5920 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.22.19-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.22.19-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.22.19-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.22.19-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.22.19-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.22.19-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.22.19-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.22.19-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.22.19-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
