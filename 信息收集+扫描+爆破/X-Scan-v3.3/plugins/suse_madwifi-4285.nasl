
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29518);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for madwifi (madwifi-4285)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch madwifi-4285");
 script_set_attribute(attribute: "description", value: "This update fixes some bugs in madwifi:
- possible security bug in radar detection code
- dynamic Beacon Interval
- Standardise Radiotap FCS Handling
- fix wrong channel change behavior for AP mode
- fix ath_hardstart returning 0 even if queue is full
- rxantenna value is reset after suspend/resume
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch madwifi-4285");
script_end_attributes();

script_summary(english: "Check for the madwifi-4285 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"madwifi-0.9.3-6.14", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"madwifi-kmp-bigsmp-0.9.3_2.6.16.53_0.8-6.14", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"madwifi-kmp-default-0.9.3_2.6.16.53_0.8-6.14", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"madwifi-kmp-smp-0.9.3_2.6.16.53_0.8-6.14", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
