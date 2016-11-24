
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41643);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for PostgreSQL (postgresql-6500)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch postgresql-6500");
 script_set_attribute(attribute: "description", value: "Multiple security vulnerabilities have been fixed in
PostgrSQL
- CVE-2009-3229: allows remote authenticated users to cause
  a denial of service
- CVE-2009-3230: allows remote authenticated users to gain
  higher privileges
- CVE-2009-3231: when using LDAP authentication with
  anonymous binds, allows remote attackers to bypass
  authentication via an empty password
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch postgresql-6500");
script_end_attributes();

script_cve_id("CVE-2009-3229", "CVE-2009-3230", "CVE-2009-3231");
script_summary(english: "Check for the postgresql-6500 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"postgresql-8.1.18-0.3", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-8.1.18-0.3", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.1.18-0.3", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-docs-8.1.18-0.3", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-libs-8.1.18-0.3", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-pl-8.1.18-0.3", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-server-8.1.18-0.3", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
