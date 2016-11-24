
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33787);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for net-snmp (net-snmp-5422)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch net-snmp-5422");
 script_set_attribute(attribute: "description", value: "This security update of net-snmp fixes a denial of service
vulnerability (CVE-2008-2292), an authentication bypass
(CVE-2008-0960) and several memory leaks.

In addition net-snmp was patched to allow customization of
the agent address set.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch net-snmp-5422");
script_end_attributes();

script_cve_id("CVE-2008-0960", "CVE-2008-2292");
script_summary(english: "Check for the net-snmp-5422 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"net-snmp-5.3.0.1-25.26", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.3.0.1-25.26", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-SNMP-5.3.0.1-25.26", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-5.3.0.1-25.24.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.3.0.1-25.24.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-SNMP-5.3.0.1-25.24.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-5.3.0.1-25.24.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.3.0.1-25.24.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-SNMP-5.3.0.1-25.24.3", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
