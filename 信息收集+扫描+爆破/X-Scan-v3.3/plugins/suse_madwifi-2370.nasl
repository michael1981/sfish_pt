
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29516);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for madwifi (madwifi-2370)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch madwifi-2370");
 script_set_attribute(attribute: "description", value: "The madwifi-ng Atheros Wireless LAN card driver is subject
to
 a remotely exploitable stack buffer overflow, this
update
 fixes this problem. (CVE-2006-6332)

This update also brings madwifi to version 0.9.2.1.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch madwifi-2370");
script_end_attributes();

script_cve_id("CVE-2006-6332");
script_summary(english: "Check for the madwifi-2370 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"madwifi-0.9.2.1-0.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"madwifi-kmp-bigsmp-0.9.2.1_2.6.16.21_0.27-0.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"madwifi-kmp-default-0.9.2.1_2.6.16.21_0.27-0.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"madwifi-kmp-smp-0.9.2.1_2.6.16.21_0.27-0.4", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
