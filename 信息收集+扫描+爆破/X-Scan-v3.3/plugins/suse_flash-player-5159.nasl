
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31964);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for flash-player (flash-player-5159)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch flash-player-5159");
 script_set_attribute(attribute: "description", value: "This flash player update to version 9.0.124.0 fixes several
security problems. In the worst case an attacker could
potentially have flash-player execute arbitrary code via
specially crafted files. (CVE-2007-5275, CVE-2007-6243,
CVE-2007-6637, CVE-2007-6019, CVE-2007-0071, CVE-2008-1655,
CVE-2008-1654)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch flash-player-5159");
script_end_attributes();

script_cve_id("CVE-2007-0071", "CVE-2007-5275", "CVE-2007-6019", "CVE-2007-6243", "CVE-2007-6637", "CVE-2008-1654", "CVE-2008-1655");
script_summary(english: "Check for the flash-player-5159 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"flash-player-9.0.124.0-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
