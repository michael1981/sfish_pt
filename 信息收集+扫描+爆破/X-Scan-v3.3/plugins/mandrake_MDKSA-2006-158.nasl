
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23902);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:158: MySQL");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:158 (MySQL).");
 script_set_attribute(attribute: "description", value: "MySQL before 4.1.13 allows local users to cause a denial of service
(persistent replication slave crash) via a query with multiupdate
and subselects. (CVE-2006-4380)
There is a bug in the MySQL-Max (and MySQL) init script where the
script was not waiting for the mysqld daemon to fully stop. This
impacted the restart beahvior during updates, as well as scripted
setups that temporarily stopped the server to backup the database
files. (Bug #15724)
The Corporate 3 and MNF2 products are not affected by these issues.
Packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:158");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4380");
script_summary(english: "Check for the version of the MySQL package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libmysql14-4.1.12-4.8.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql14-devel-4.1.12-4.8.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.1.12-4.8.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.1.12-4.8.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.1.12-4.8.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.1.12-4.8.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.1.12-4.8.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-NDB-4.1.12-4.8.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"MySQL-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-4380", value:TRUE);
}
exit(0, "Host is not affected");
