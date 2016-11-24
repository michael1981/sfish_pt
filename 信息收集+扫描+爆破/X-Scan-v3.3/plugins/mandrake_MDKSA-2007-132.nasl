
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25598);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:132: madwifi-source");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:132 (madwifi-source).");
 script_set_attribute(attribute: "description", value: "The 802.11 network stack in MadWifi prior to 0.9.3.1 would alloa remote
attackers to cause a denial of service (system hang) via a crafted
length field in nested 802.3 Ethernet frames in Fast Frame packets,
which results in a NULL pointer dereference (CVE-2007-2829).
The ath_beacon_config function in MadWifi prior to 0.9.3.1 would
allow a remote attacker to cause a denial of service (system crash)
via crafted beacon interval information when scanning for access
points, which triggered a divide-by-zero error (CVE-2007-2830).
An array index error in MadWifi prior to 0.9.3.1 would allow a
local user to cause a denial of service (system crash) and possibly
obtain kerenl memory contents, as well as possibly allowing for the
execution of arbitrary code via a large negative array index value
(CVE-2007-2831).
Updated packages have been updated to 0.9.3.1 to correct these
issues. Wpa_supplicant is built using madwifi-source and has been
rebuilt using 0.9.3.1 source.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:132");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-2829", "CVE-2007-2830", "CVE-2007-2831");
script_summary(english: "Check for the version of the madwifi-source package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"madwifi-source-0.9.3.1-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wpa_gui-0.5.5-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wpa_supplicant-0.5.5-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-source-0.9.3.1-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-source-0.9.3.1-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wpa_gui-0.5.7-1.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wpa_supplicant-0.5.7-1.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-source-0.9.3.1-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"madwifi-source-", release:"MDK2007.0")
 || rpm_exists(rpm:"madwifi-source-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-2829", value:TRUE);
 set_kb_item(name:"CVE-2007-2830", value:TRUE);
 set_kb_item(name:"CVE-2007-2831", value:TRUE);
}
exit(0, "Host is not affected");
