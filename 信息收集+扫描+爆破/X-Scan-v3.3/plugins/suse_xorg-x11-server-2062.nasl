
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29605);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for xorg-x11-server (xorg-x11-server-2062)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xorg-x11-server-2062");
 script_set_attribute(attribute: "description", value: "This update fixes an integer overflow vulnerability when
rendering CID-keyed fonts (CVE-2006-3739/CVE-2006-3740).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch xorg-x11-server-2062");
script_end_attributes();

script_cve_id("CVE-2006-3739", "CVE-2006-3740");
script_summary(english: "Check for the xorg-x11-server-2062 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"xorg-x11-server-6.9.0-50.24", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xorg-x11-server-6.9.0-50.24", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
