
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25669);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:139: MySQL");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:139 (MySQL).");
 script_set_attribute(attribute: "description", value: "MySQL 5.x before 5.0.36 allows local users to cause a denial of service
(database crash) by performing information_schema table subselects
and using ORDER BY to sort a single-row result, which prevents
certain structure elements from being initialized and triggers a
NULL dereference in the filesort function. This issue does not affect
MySQL 5.0.37 in Mandriva Linux 2007.1. (CVE-2007-1420)
The in_decimal::set function in item_cmpfunc.cc in MySQL before 5.0.40,
and 5.1 before 5.1.18-beta, allows context-dependent attackers to cause
a denial of service (crash) via a crafted IF clause that results in
a divide-by-zero error and a NULL pointer dereference. (CVE-2007-2583)
MySQL before 4.1.23, 5.0.x before 5.0.42, and 5.1.x before 5.1.18
does not require the DROP privilege for RENAME TABLE statements,
which allows remote authenticated users to rename arbitrary
tables. (CVE-2007-2691)
Updated packages have been patched to prevent the above issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:139");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-1420", "CVE-2007-2583", "CVE-2007-2691");
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

if ( rpm_check( reference:"MySQL-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-ndb-extra-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-ndb-management-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-ndb-storage-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-ndb-tools-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql15-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql15-devel-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql15-static-devel-5.0.24a-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-Max-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-bench-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-client-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-common-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-ndb-extra-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-ndb-management-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-ndb-storage-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"MySQL-ndb-tools-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql15-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql15-devel-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql15-static-devel-5.0.37-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"MySQL-", release:"MDK2007.0")
 || rpm_exists(rpm:"MySQL-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-1420", value:TRUE);
 set_kb_item(name:"CVE-2007-2583", value:TRUE);
 set_kb_item(name:"CVE-2007-2691", value:TRUE);
}
exit(0, "Host is not affected");
