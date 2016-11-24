
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33887);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  pdns-recursor: improved spoofing resistance (pdns-5510)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch pdns-5510");
 script_set_attribute(attribute: "description", value: "This update of pdns offers better spoofing resistance by
not ignoring invalid queries. (CVE-2008-3337)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch pdns-5510");
script_end_attributes();

script_cve_id("CVE-2008-3337");
script_summary(english: "Check for the pdns-5510 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"pdns-2.9.21-57.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pdns-backend-ldap-2.9.21-57.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pdns-backend-mysql-2.9.21-57.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pdns-backend-postgresql-2.9.21-57.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pdns-backend-sqlite2-2.9.21-57.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"pdns-backend-sqlite3-2.9.21-57.3", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
