
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24531);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKA-2006:056: drakxtools");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKA-2006:056 (drakxtools).");
 script_set_attribute(attribute: "description", value: "Several bugs were fixed in drakxtools:
- it was not possible to start rpmdrake from the menu (#26383) - it was
not possible to set up updates media and then distro media (or the
reverse) in edit-urpm-sources - drakauth: o add encrypted home and
pam_mount support o hide password when calling 'net join' or 'net ads
join' (pixel) - drakbackup: o fix archiver detection/config file
replace (stew, #26705, #27180) o do not backup the backups (Adamw) -
drakboot: support Xen with lilo using mbootpack - drakfirewall: really
disable services (#27295) - drakvpn: o add pkcs11 token support for
openvpn o ask password/PIN if needed - drakconnect/drakroam: o detect
wireless interfaces with unknown driver, e.g. rt61 o do not check for
ipw3945 kernel module packages o do not wrongly tell that
acx100-firmware can be found in Club or commercial editions (#26475) o
use iwpriv commands to configure WPA on rt2570 and rt61 chipsets o
update madwifi URL which was old - finish-install: add encrypted home
and pam_mount support - printerdrake: due to changes in the format of
HPLIP's device description XML files, scanner functionality was not
recognized any more (#26567).
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKA-2006:056");
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

if ( rpm_check( reference:"drakx-finish-install-10.4.81-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-10.4.81-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-backend-10.4.81-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-http-10.4.81-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"drakxtools-newt-10.4.81-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"harddrake-10.4.81-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"harddrake-ui-10.4.81-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
