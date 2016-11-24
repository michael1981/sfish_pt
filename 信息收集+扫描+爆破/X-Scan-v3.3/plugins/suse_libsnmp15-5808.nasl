
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35027);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  net-snmp security update (libsnmp15-5808)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libsnmp15-5808");
 script_set_attribute(attribute: "description", value: "Remote attackers could crash net-snmp via GETBULK-Request
(CVE-2008-4309).

In addition the following non-security issues have been
fixed:

- typo in error message (bnc#439857)
- fix duplicate registration warnings on startup
  (bnc#326957)
- container insert errors reproducable with shared ip
  setups (bnc#396773)
- typo in the snmpd init script to really load all agents
  (bnc#415127)
- logrotate config to restart the snmptrapd aswell
  (bnc#378069)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libsnmp15-5808");
script_end_attributes();

script_cve_id("CVE-2008-4309");
script_summary(english: "Check for the libsnmp15-5808 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libsnmp15-5.4.1-19.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-5.4.1-19.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-32bit-5.4.1-19.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-64bit-5.4.1-19.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.4.1-19.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-64bit-5.4.1-19.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-SNMP-5.4.1-19.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"snmp-mibs-5.4.1-19.4", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
