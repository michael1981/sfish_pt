
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36943);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:094: mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:094 (mysql).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in mysql:
MySQL 5.0 before 5.0.66, 5.1 before 5.1.26, and 6.0 before 6.0.6
does not properly handle a b'' (b single-quote single-quote) token,
aka an empty bit-string literal, which allows remote attackers to
cause a denial of service (daemon crash) by using this token in a
SQL statement (CVE-2008-3963).
MySQL 5.0.51a allows local users to bypass certain privilege checks by
calling CREATE TABLE on a MyISAM table with modified (1) DATA DIRECTORY
or (2) INDEX DIRECTORY arguments that are associated with symlinks
within pathnames for subdirectories of the MySQL home data directory,
which are followed when tables are created in the future. NOTE: this
vulnerability exists because of an incomplete fix for CVE-2008-2079
(CVE-2008-4097).
MySQL before 5.0.67 allows local users to bypass certain privilege
checks by calling CREATE TABLE on a MyISAM table with modified (1)
DATA DIRECTORY or (2) INDEX DIRECTORY arguments that are originally
associated with pathnames without symlinks, and that can point to
tables created at a future time at which a pathname is modified
to contain a symlink to a subdirectory of the MySQL home data
directory. NOTE: this vulnerability exists because of an incomplete
fix for CVE-2008-4097 (CVE-2008-4098).
Cross-site scripting (XSS) vulnerability in the command-line client
in MySQL 5.0.26 through 5.0.45, when the --html option is enabled,
allows attackers to inject arbitrary web script or HTML by placing
it in a database cell, which might be accessed by this client when
composing an HTML document (CVE-2008-4456).
bugs in the Mandriva Linux 2008.1 packages that has been fixed:
o upstream fix for mysql bug35754 (#38398, #44691)
o fix #46116 (initialization file mysqld-max don't show correct
application status)
o fix upstream bug 42366
bugs in the Mandriva Linux 2009.0 packages that has been fixed:
o upgraded 5.0.67 to 5.0.77 (fixes CVE-2008-3963, CVE-2008-4097,
CVE-2008-4098)
o no need to workaround #38398, #44691 anymore (since 5.0.75)
o fix upstream bug 42366
o fix #46116 (initialization file mysqld-max don't show correct
application status)
o sphinx-0.9.8.1
bugs in the Mandriva Linux Corporate Server 4 packages that has
been fixed:
o fix upstream bug 42366
o fix #46116 (initialization file mysqld-max don't show correct
application status)
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:094");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-2079", "CVE-2008-3963", "CVE-2008-4097", "CVE-2008-4098", "CVE-2008-4456");
script_summary(english: "Check for the version of the mysql package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libmysql15-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql-devel-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql-static-devel-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-client-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-common-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-doc-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-max-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-ndb-extra-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-ndb-management-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-ndb-storage-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-ndb-tools-5.0.51a-8.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql15-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql-devel-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmysql-static-devel-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-client-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-common-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-doc-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-max-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-ndb-extra-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-ndb-management-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-ndb-storage-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-ndb-tools-5.0.77-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mysql-", release:"MDK2008.1")
 || rpm_exists(rpm:"mysql-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-2079", value:TRUE);
 set_kb_item(name:"CVE-2008-3963", value:TRUE);
 set_kb_item(name:"CVE-2008-4097", value:TRUE);
 set_kb_item(name:"CVE-2008-4098", value:TRUE);
 set_kb_item(name:"CVE-2008-4456", value:TRUE);
}
exit(0, "Host is not affected");
