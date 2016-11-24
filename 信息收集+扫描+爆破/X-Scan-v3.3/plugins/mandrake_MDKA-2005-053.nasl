
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24479);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKA-2005:053: drakxtools");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKA-2005:053 (drakxtools).");
 script_set_attribute(attribute: "description", value: "A number of bugs have been fixed in this new drakxtools package,
primarily within the drakconnect and XFdrake programs:
The package requires perl-suid for fileshareset and filesharelist.
Drakconnect fixes include:
- don't duplicate variables (MTU, NETMASK, IPADDR) in ifcfg files
- don't let interfaces with unknown drivers be configured
- set hostname only after packages have been installed, thus preventing
a potential failure in the graphical urpmi
- workaround to have device-independant configuration files in wireless.d
- workaround missing 'device' link in sysfs for rt2400/rt2500
- fix zd1201 device detection
Net_applet fixes include:
- use disconnected icon if no route, even if wifi is associated
XFdrake fixes include:
- handle nvidia_legacy
- prevent x11 segfaulting with nvidia driver (loading both Xorg's glx
and nvidia's glx)
- prevent GL applications from segfaulting when using the nv driver
while nvidia packages are being installed
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKA-2005:053");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the drakxtools package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"drakx-finish-install-10.3-0.64.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-10.3-0.64.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-backend-10.3-0.64.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-http-10.3-0.64.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-newt-10.3-0.64.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"harddrake-10.3-0.64.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"harddrake-ui-10.3-0.64.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
