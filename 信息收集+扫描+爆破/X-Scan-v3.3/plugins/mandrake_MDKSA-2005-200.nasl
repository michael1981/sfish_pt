
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20126);
 script_version ("$Revision: 1.4 $");
 script_name(english: "MDKSA-2005:200: apache-mod_auth_shadow");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:200 (apache-mod_auth_shadow).");
 script_set_attribute(attribute: "description", value: "The mod_auth_shadow module 1.0 through 1.5 and 2.0 for Apache with
AuthShadow enabled uses shadow authentication for all locations that
use the require group directive, even when other authentication
mechanisms are specified, which might allow remote authenticated users
to bypass security restrictions.
This update requires an explicit 'AuthShadow on' statement if website
authentication should be checked against /etc/shadow.
The updated packages have been patched to address this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:200");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2963");
script_summary(english: "Check for the version of the apache-mod_auth_shadow package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apache2-mod_auth_shadow-2.0.50_2.0-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_auth_shadow-2.0.53_2.0-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_auth_shadow-2.0.54_2.0-4.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"apache-mod_auth_shadow-", release:"MDK10.1")
 || rpm_exists(rpm:"apache-mod_auth_shadow-", release:"MDK10.2")
 || rpm_exists(rpm:"apache-mod_auth_shadow-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2963", value:TRUE);
}
exit(0, "Host is not affected");
