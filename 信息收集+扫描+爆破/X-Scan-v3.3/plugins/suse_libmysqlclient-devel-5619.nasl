
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35248);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  mysql security update (libmysqlclient-devel-5619)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libmysqlclient-devel-5619");
 script_set_attribute(attribute: "description", value: "Empty bit-strings in a query could crash the MySQL server
(CVE-2008-3963).

Due to another flaw users could access tables of other
users  (CVE-2008-4097, CVE-2008-4098).

This update also fixes the previously broken mysqlhotcopy
script.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libmysqlclient-devel-5619");
script_end_attributes();

script_cve_id("CVE-2008-3963", "CVE-2008-4097", "CVE-2008-4098");
script_summary(english: "Check for the libmysqlclient-devel-5619 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libmysqlclient-devel-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient15-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient15-32bit-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient15-64bit-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient_r15-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient_r15-32bit-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libmysqlclient_r15-64bit-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-Max-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-bench-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-client-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-debug-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-tools-5.0.45-22.7", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
