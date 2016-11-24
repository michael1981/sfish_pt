
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33885);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  mysql: Fixes a security problem (libmysqlclient-devel-5341)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libmysqlclient-devel-5341");
 script_set_attribute(attribute: "description", value: "The database server MySQL was updated to fix a security
problem:

CVE-2008-2079: MySQL allowed local users to bypass certain
privilege checks by calling CREATE TABLE on a MyISAM table
with modified (1) DATA DIRECTORY or (2) INDEX DIRECTORY
arguments that are within the MySQL home data directory,
which can point to tables that are created in the future.

CVE-2006-7232: sql_select.cc in MySQL 5.0.x before 5.0.32
and 5.1.x before 5.1.14 allows remote authenticated users
to cause a denial of service (crash) via an EXPLAIN SELECT
FROM on the INFORMATION_SCHEMA table, as originally
demonstrated using ORDER BY.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libmysqlclient-devel-5341");
script_end_attributes();

script_cve_id("CVE-2008-2079", "CVE-2006-7232");
script_summary(english: "Check for the libmysqlclient-devel-5341 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libmysqlclient-devel-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient15-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient15-32bit-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient15-64bit-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient_r15-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient_r15-32bit-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient_r15-64bit-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-Max-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-bench-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-client-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-debug-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-tools-5.0.45-22.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
