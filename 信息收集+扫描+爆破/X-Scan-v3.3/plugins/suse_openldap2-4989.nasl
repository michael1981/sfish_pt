
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32078);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for OpenLDAP 2 (openldap2-4989)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch openldap2-4989");
 script_set_attribute(attribute: "description", value: "Authenticated users could crash the LDAP server 'slapd' via
the 'NOOP' command (CVE-2007-6698,CVE-2008-0658)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch openldap2-4989");
script_end_attributes();

script_cve_id("CVE-2007-6698", "CVE-2008-0658");
script_summary(english: "Check for the openldap2-4989 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"openldap2-2.3.32-0.25.5", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-back-meta-2.3.32-0.25.5", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-back-perl-2.3.32-0.25.5", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-client-2.3.32-0.23.5", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-devel-2.3.32-0.23.5", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-2.3.32-0.25.5", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-client-2.3.32-0.23.5", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"openldap2-devel-2.3.32-0.23.5", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
