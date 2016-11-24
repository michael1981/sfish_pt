
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31404);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  wireshark: Fix for three vulnerabilities. (wireshark-5057)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch wireshark-5057");
 script_set_attribute(attribute: "description", value: "This update fixes the following bugs:
- the SCTP dissector could crash
- the SNMP dissector could crash
- the TFTP dissector could crash Wireshark (maybe a bug in
  the Cairo library on specific platforms)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch wireshark-5057");
script_end_attributes();

script_summary(english: "Check for the wireshark-5057 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"wireshark-0.99.6-31.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"wireshark-devel-0.99.6-31.5", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
