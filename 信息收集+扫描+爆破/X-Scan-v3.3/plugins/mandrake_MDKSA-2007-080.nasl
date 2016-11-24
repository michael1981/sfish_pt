
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24946);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:080-1: tightvnc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:080-1 (tightvnc).");
 script_set_attribute(attribute: "description", value: "Local exploitation of a memory corruption vulnerability in the X.Org
and XFree86 X server could allow an attacker to execute arbitrary
code with privileges of the X server, typically root.
The vulnerability exists in the ProcXCMiscGetXIDList() function in the
XC-MISC extension. This request is used to determine what resource IDs
are available for use. This function contains two vulnerabilities,
both result in memory corruption of either the stack or heap. The
ALLOCATE_LOCAL() macro used by this function allocates memory on the
stack using alloca() on systems where alloca() is present, or using
the heap otherwise. The handler function takes a user provided value,
multiplies it, and then passes it to the above macro. This results in
both an integer overflow vulnerability, and an alloca() stack pointer
shifting vulnerability. Both can be exploited to execute arbitrary
code. (CVE-2007-1003)
iDefense reported two integer overflows in the way X.org handled
various font files. A malicious local user could exploit these issues
to potentially execute arbitrary code with the privileges of the
X.org server. (CVE-2007-1351, CVE-2007-1352)
TightVNC uses some of the same code base as Xorg, and has the same
vulnerable code.
Updated packages are patched to address these issues.
Update:
Packages for Mandriva Linux 2007.1 are now available.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:080-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352");
script_summary(english: "Check for the version of the tightvnc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tightvnc-1.2.9-16.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tightvnc-doc-1.2.9-16.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tightvnc-server-1.2.9-16.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"tightvnc-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-1003", value:TRUE);
 set_kb_item(name:"CVE-2007-1351", value:TRUE);
 set_kb_item(name:"CVE-2007-1352", value:TRUE);
}
exit(0, "Host is not affected");
