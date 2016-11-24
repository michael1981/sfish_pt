
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30182);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for MySQL (mysql-4879)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch mysql-4879");
 script_set_attribute(attribute: "description", value: "This update fixes several security vulnerabilities (note:
not all versions are affected by every bug): 
- CVE-2007-2583 
- CVE-2007-2691 
- CVE-2007-2692 
- CVE-2007-5925 
- CVE-2007-5969 
- CVE-2007-6303 
- CVE-2007-6304
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch mysql-4879");
script_end_attributes();

script_cve_id("CVE-2007-2583", "CVE-2007-2691", "CVE-2007-2692", "CVE-2007-5925", "CVE-2007-5969", "CVE-2007-6303", "CVE-2007-6304");
script_summary(english: "Check for the mysql-4879 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"mysql-5.0.26-12.16", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-Max-5.0.26-12.16", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-client-5.0.26-12.16", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-devel-5.0.26-12.16", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-shared-5.0.26-12.16", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-5.0.26-12.16", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-client-5.0.26-12.16", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-devel-5.0.26-12.16", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mysql-shared-5.0.26-12.16", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
