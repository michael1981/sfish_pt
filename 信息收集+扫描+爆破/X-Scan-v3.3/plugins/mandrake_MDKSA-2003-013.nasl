
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13998);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:013: MYSQL");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:013 (MYSQL).");
 script_set_attribute(attribute: "description", value: "Aleksander Adamowski informed MandrakeSoft that the MySQL developers
fixed a DoS vulnerability in the recently released 3.23.55 version
of MySQL. A double free() pointer bug in the mysql_change_user()
handling would allow a specially hacked mysql client to crash the
main mysqld server. This vulnerability can only be exploited by first
logging in with a valid user account.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:013");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0073");
script_summary(english: "Check for the version of the MYSQL package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"MySQL-3.23.31-1.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-3.23.31-1.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-3.23.31-1.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-devel-3.23.31-1.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-shared-3.23.31-1.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-3.23.36-2.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-3.23.36-2.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-3.23.36-2.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-devel-3.23.36-2.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-shared-3.23.36-2.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-3.23.41-5.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-3.23.41-5.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-3.23.41-5.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-devel-3.23.41-5.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-shared-3.23.41-5.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql10-3.23.47-5.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql10-devel-3.23.47-5.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-3.23.47-5.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-3.23.47-5.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-3.23.47-5.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql10-3.23.52-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql10-devel-3.23.52-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-3.23.52-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-3.23.52-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-3.23.52-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-3.23.52-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"MYSQL-", release:"MDK7.2")
 || rpm_exists(rpm:"MYSQL-", release:"MDK8.0")
 || rpm_exists(rpm:"MYSQL-", release:"MDK8.1")
 || rpm_exists(rpm:"MYSQL-", release:"MDK8.2")
 || rpm_exists(rpm:"MYSQL-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0073", value:TRUE);
}
exit(0, "Host is not affected");
