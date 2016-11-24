
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38035);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:218: lynx");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:218 (lynx).");
 script_set_attribute(attribute: "description", value: "A vulnerability was found in the Lynxcgi: URI handler that could allow
an attacker to create a web page redirecting to a malicious URL that
would execute arbitrary code as the user running Lynx, if they were
using the non-default Advanced user mode (CVE-2008-4690).
This update corrects these issues and, in addition, makes Lynx always
prompt the user before loading a lynxcgi: URI. As well, the default
lynx.cfg configuration file marks all lynxcgi: URIs as untrusted.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:218");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-4690");
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

if ( rpm_check( reference:"lynx-2.8.6-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.6-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.6-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"lynx-", release:"MDK2008.0")
 || rpm_exists(rpm:"lynx-", release:"MDK2008.1")
 || rpm_exists(rpm:"lynx-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-4690", value:TRUE);
}
exit(0, "Host is not affected");
