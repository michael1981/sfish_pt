
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23896);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:149: MySQL");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:149 (MySQL).");
 script_set_attribute(attribute: "description", value: "MySQL 4.1 before 4.1.21 and 5.0 before 5.0.24 allows a local user to
access a table through a previously created MERGE table, even after the
user's privileges are revoked for the original table, which might
violate intended security policy (CVE-2006-4031).
The update allows the local admin to override MERGE using the
'--skip-merge' option when running mysqld. This can be defined under
MYSQLD_OPTIONS in /etc/sysconfig/mysqld. If '--skip-merge' is not used,
the old behaviour of MERGE tables is still used.
MySQL 4.1 before 4.1.21, 5.0 before 5.0.25, and 5.1 before 5.1.12,
when run on case-sensitive filesystems, allows remote authenticated
users to create or access a database when the database name differs
only in case from a database for which they have permissions
(CVE-2006-4226).
Packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:149");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4031", "CVE-2006-4226");
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

if ( rpm_check( reference:"libmysql14-4.1.12-4.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql14-devel-4.1.12-4.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-4.1.12-4.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-4.1.12-4.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-4.1.12-4.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-4.1.12-4.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-4.1.12-4.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-NDB-4.1.12-4.6.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"MySQL-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-4031", value:TRUE);
 set_kb_item(name:"CVE-2006-4226", value:TRUE);
}
exit(0, "Host is not affected");
