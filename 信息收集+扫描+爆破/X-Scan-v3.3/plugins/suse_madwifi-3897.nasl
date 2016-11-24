
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29517);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for madwifi (madwifi-3897)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch madwifi-3897");
 script_set_attribute(attribute: "description", value: "The madwifi driver and userland packages were updated to
0.9.3.1. Please note that while the RPM version still says
'0.9.3', the content is the 0.9.3.1 version.

This updates fixes following security problems:

CVE-2007-2829: The 802.11 network stack in
net80211/ieee80211_input.c in MadWifi before 0.9.3.1 allows
remote attackers to cause a denial of service (system hang)
via a crafted length field in nested 802.3 Ethernet frames
in Fast Frame packets, which results in a NULL pointer
dereference.

CVE-2007-2830: The ath_beacon_config function in if_ath.c
in MadWifi before 0.9.3.1 allows remote attackers to cause
a denial of service (system crash) via crafted beacon
interval information when scanning for access points, which
triggers a divide-by-zero error.

CVE-2007-2831: Array index error in the (1)
ieee80211_ioctl_getwmmparams and (2)
ieee80211_ioctl_setwmmparams functions in
net80211/ieee80211_wireless.c in MadWifi before 0.9.3.1
allows local users to cause a denial of service (system
crash), possibly obtain kernel memory contents, and
possibly execute arbitrary code via a large negative array
index value.

'remote attackers' are attackers within range of the WiFi
reception of the card.

Please note that the problems fixed in 0.9.3 were fixed by
the madwifi Version upgrade to 0.9.3 in SLE10 Service Pack
1. (CVE-2005-4835, CVE-2006-7177, CVE-2006-7178,
CVE-2006-7179, CVE-2006-7180).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch madwifi-3897");
script_end_attributes();

script_cve_id("CVE-2005-4835", "CVE-2006-7177", "CVE-2006-7178", "CVE-2006-7179", "CVE-2006-7180", "CVE-2007-2829", "CVE-2007-2830", "CVE-2007-2831");
script_summary(english: "Check for the madwifi-3897 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"madwifi-0.9.3-6.11", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"madwifi-kmp-bigsmp-0.9.3_2.6.16.46_0.16-6.11", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"madwifi-kmp-default-0.9.3_2.6.16.46_0.16-6.11", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"madwifi-kmp-smp-0.9.3_2.6.16.46_0.16-6.11", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
