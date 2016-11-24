
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36715);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2009:031: drakx-net");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2009:031 (drakx-net).");
 script_set_attribute(attribute: "description", value: "This update several minor issues with Mandriva Network tools
(drakx-net).
- drakroam would crash if no wireless interface is present on the
system.
- Cancel button of Interactive Firewall configuration screen of
drakfirewall was not handled correctly (bug #46256)
- Interactive Firewall settings were not applied immediately after
changing firewall configuration (bug #47370)
- Unicode dates were not displayed correctly in drakids (bug #39914)
- Network interface name was not displayed in drakconnect, leading
to confusion when several identical cards are present in the system
(bug #45881)
- When guessing DNS and GW addresses for static address connections,
the guessed IPs were different (bug #7041)
- Network monitor would display negative traffic amount when
transferring over 4GB of data (bug #46398)
- Custom MTU values were not preserved when changing network
configuration using drakconnect (bug #45969)
- The excessive number of failed connection attempts to ADSL networks
could lead to extremely long boot times (bug #28087).
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2009:031");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the drakx-net package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"drakx-net-0.54.4-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakx-net-text-0.54.4-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdrakx-net-0.54.4-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakx-net-0.54.4-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakx-net-text-0.54.4-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdrakx-net-0.54.4-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
