
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42811);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:300: apache-conf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:300 (apache-conf).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered and corrected in apache-conf:
The Apache HTTP Server enables the HTTP TRACE method per default
which allows remote attackers to conduct cross-site scripting (XSS)
attacks via unspecified web client software (CVE-2009-2823).
This update provides a solution to this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:300");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-2823");
script_summary(english: "Check for the version of the apache-conf package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apache-conf-2.2.9-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-conf-2.2.11-5.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-conf-2.2.9-2.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-conf-2.2.14-1.1mdv2010.0", release:"MDK2010.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"apache-conf-", release:"MDK2009.0")
 || rpm_exists(rpm:"apache-conf-", release:"MDK2009.1")
 || rpm_exists(rpm:"apache-conf-", release:"MDK2010.0") )
{
 set_kb_item(name:"CVE-2009-2823", value:TRUE);
}
exit(0, "Host is not affected");
