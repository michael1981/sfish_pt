
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42070);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  wireshark security update (wireshark-6533)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch wireshark-6533");
 script_set_attribute(attribute: "description", value: "Specially crafted packets could crash the OPC UA dissector
in Wireshark (CVE-2009-3241)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch wireshark-6533");
script_end_attributes();

script_cve_id("CVE-2009-3241");
script_summary(english: "Check for the wireshark-6533 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"wireshark-0.99.6-31.22", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"wireshark-devel-0.99.6-31.22", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
