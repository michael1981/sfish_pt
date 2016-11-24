
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25033);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:082: madwifi-source");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:082 (madwifi-source).");
 script_set_attribute(attribute: "description", value: "The ath_rate_sample function in the ath_rate/sample/sample.c sample
code in MadWifi before 0.9.3 allows remote attackers to cause a denial
of service (failed KASSERT and system crash) by moving a connected
system to a location with low signal strength, and possibly other
vectors related to a race condition between interface enabling and
packet transmission. (CVE-2005-4835)
MadWifi, when Ad-Hoc mode is used, allows remote attackers to cause
a denial of service (system crash) via unspecified vectors that lead
to a kernel panic in the ieee80211_input function, related to packets
coming from a malicious WinXP system. (CVE-2006-7177)
MadWifi before 0.9.3 does not properly handle reception of an AUTH
frame by an IBSS node, which allows remote attackers to cause a denial
of service (system crash) via a certain AUTH frame. (CVE-2006-7178)
ieee80211_input.c in MadWifi before 0.9.3 does not properly process
Channel Switch Announcement Information Elements (CSA IEs), which
allows remote attackers to cause a denial of service (loss of
communication) via a Channel Switch Count less than or equal to one,
triggering a channel change. (CVE-2006-7179)
ieee80211_output.c in MadWifi before 0.9.3 sends unencrypted packets
before WPA authentication succeeds, which allows remote attackers
to obtain sensitive information (related to network structure),
and possibly cause a denial of service (disrupted authentication)
and conduct spoofing attacks. (CVE-2006-7180)
Updated packages have been updated to 0.9.3 to correct this
issue. Wpa_supplicant is built using madwifi-source and has been
rebuilt using 0.9.3 source.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:082");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-4835", "CVE-2006-7177", "CVE-2006-7178", "CVE-2006-7179", "CVE-2006-7180");
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

if ( rpm_check( reference:"madwifi-source-0.9.3-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wpa_gui-0.5.5-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wpa_supplicant-0.5.5-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-source-0.9.3-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-source-0.9.3-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wpa_gui-0.5.7-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wpa_supplicant-0.5.7-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"madwifi-source-0.9.3-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"madwifi-source-", release:"MDK2007.0")
 || rpm_exists(rpm:"madwifi-source-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2005-4835", value:TRUE);
 set_kb_item(name:"CVE-2006-7177", value:TRUE);
 set_kb_item(name:"CVE-2006-7178", value:TRUE);
 set_kb_item(name:"CVE-2006-7179", value:TRUE);
 set_kb_item(name:"CVE-2006-7180", value:TRUE);
}
exit(0, "Host is not affected");
