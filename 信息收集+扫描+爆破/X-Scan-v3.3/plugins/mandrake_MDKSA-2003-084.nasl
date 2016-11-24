
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14066);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:084: perl-CGI");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:084 (perl-CGI).");
 script_set_attribute(attribute: "description", value: "Eye on Security found a cross-site scripting vulnerability in the
start_form() function in CGI.pm. This vulnerability allows a remote
attacker to place a web script in a URL which feeds into a form's
action parameter and allows execution by the browser as if it was
coming from the site.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:084");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0615");
script_summary(english: "Check for the version of the perl-CGI package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-CGI-3.00-0.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-CGI-3.00-0.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-CGI-3.00-0.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"perl-CGI-", release:"MDK8.2")
 || rpm_exists(rpm:"perl-CGI-", release:"MDK9.0")
 || rpm_exists(rpm:"perl-CGI-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0615", value:TRUE);
}
exit(0, "Host is not affected");
