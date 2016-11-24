
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14008);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:023: lynx");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:023 (lynx).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in lynx, a text-mode web browser. The
HTTP queries that lynx constructs are from arguments on the command
line or the $WWW_HOME environment variable, but lynx does not properly
sanitize special characters such as carriage returns or linefeeds.
Extra headers can be inserted into the request because of this, which
can cause scripts that use lynx to fetch data from the wrong site from
servers that use virtual hosting.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:023");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1405");
script_summary(english: "Check for the version of the lynx package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lynx-2.8.5-0.10mdk.dev.8", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-0.10mdk.dev.8", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-0.10mdk.dev.8", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-0.10mdk.dev.8", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-0.10mdk.dev.8", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"lynx-", release:"MDK7.2")
 || rpm_exists(rpm:"lynx-", release:"MDK8.0")
 || rpm_exists(rpm:"lynx-", release:"MDK8.1")
 || rpm_exists(rpm:"lynx-", release:"MDK8.2")
 || rpm_exists(rpm:"lynx-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1405", value:TRUE);
}
exit(0, "Host is not affected");
