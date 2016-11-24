
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41562);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for net-snmp (net-snmp-6248)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch net-snmp-6248");
 script_set_attribute(attribute: "description", value: "With this update of net-snmp the handling of TCP wrappers
rules for client authorization was improved, prior to this
update it was possible for remote attackers to bypass
intended access restrictions and execute SNMP queries.
(CVE-2008-6123)  Additionally binding to multiple
interfaces was improved.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch net-snmp-6248");
script_end_attributes();

script_cve_id("CVE-2008-6123");
script_summary(english: "Check for the net-snmp-6248 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"net-snmp-5.3.0.1-25.31", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.3.0.1-25.31", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-SNMP-5.3.0.1-25.31", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
