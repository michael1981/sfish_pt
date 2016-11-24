
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29882);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  net-snmp: Fix for denial-of-service. (net-snmp-4753)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch net-snmp-4753");
 script_set_attribute(attribute: "description", value: "This update of net-snmp fixes the following bugs: 
- default and configurable maximum number of varbinds
  returnable to  a GETBULK request (CVE-2007-5846) 
- crash when smux peers were configured with empty
  passwords 
- the UCD-SNMP-MIB::memCached.0 SNMP object was missing 
- the snmptrap command from the net-snmp package sends
  traps per default on the wrong port.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch net-snmp-4753");
script_end_attributes();

script_cve_id("CVE-2007-5846");
script_summary(english: "Check for the net-snmp-4753 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"net-snmp-5.4.rc2-6", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-32bit-5.4.rc2-6", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-64bit-5.4.rc2-6", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.4.rc2-6", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-64bit-5.4.rc2-6", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-SNMP-5.4.rc2-6", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
