
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16359);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:030: perl-DBI");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:030 (perl-DBI).");
 script_set_attribute(attribute: "description", value: "Javier Fernandez-Sanguino Pena disovered the perl5 DBI library created
a temporary PID file in an insecure manner, which could be exploited
by a malicious user to overwrite arbitrary files owned by the user
executing the parts of the library.
The updated packages have been patched to prevent these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:030");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0077");
script_summary(english: "Check for the version of the perl-DBI package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-DBI-1.40-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-ProfileDumper-Apache-1.40-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-proxy-1.40-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-1.43-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-ProfileDumper-Apache-1.43-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-proxy-1.43-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-1.38-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-ProfileDumper-Apache-1.38-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-proxy-1.38-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"perl-DBI-", release:"MDK10.0")
 || rpm_exists(rpm:"perl-DBI-", release:"MDK10.1")
 || rpm_exists(rpm:"perl-DBI-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2005-0077", value:TRUE);
}
exit(0, "Host is not affected");
