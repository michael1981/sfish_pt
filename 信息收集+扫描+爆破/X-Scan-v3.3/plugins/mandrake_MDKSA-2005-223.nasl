
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20454);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2005:223: webmin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:223 (webmin).");
 script_set_attribute(attribute: "description", value: "Jack Louis discovered a format string vulnerability in miniserv.pl
Perl web server in Webmin before 1.250 and Usermin before 1.180,
with syslog logging enabled. This can allow remote attackers to cause
a denial of service (crash or memory consumption) and possibly execute
arbitrary code via format string specifiers in the username parameter
to the login form, which is ultimately used in a syslog call.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:223");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-3912");
script_summary(english: "Check for the version of the webmin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"webmin-1.150-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"webmin-1.180-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"webmin-1.220-9.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"webmin-", release:"MDK10.1")
 || rpm_exists(rpm:"webmin-", release:"MDK10.2")
 || rpm_exists(rpm:"webmin-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3912", value:TRUE);
}
exit(0, "Host is not affected");
