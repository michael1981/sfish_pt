
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36812);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:062: shadow-utils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:062 (shadow-utils).");
 script_set_attribute(attribute: "description", value: "A security vulnerability has been identified and fixed in login
application from shadow-utils, which could allow local users in
the utmp group to overwrite arbitrary files via a symlink attack on
a temporary file referenced in a line (aka ut_line) field in a utmp
entry (CVE-2008-5394).
The updated packages have been patched to prevent this.
Note: Mandriva Linux is using login application from util-linux-ng
by default, and therefore is not affected by this issue on default
configuration.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:062");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-5394");
script_summary(english: "Check for the version of the shadow-utils package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"shadow-utils-4.0.12-8.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"shadow-utils-4.0.12-9.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"shadow-utils-4.0.12-17.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"shadow-utils-", release:"MDK2008.0")
 || rpm_exists(rpm:"shadow-utils-", release:"MDK2008.1")
 || rpm_exists(rpm:"shadow-utils-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-5394", value:TRUE);
}
exit(0, "Host is not affected");
