
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27314);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  ktorrent security update (ktorrent-3057)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ktorrent-3057");
 script_set_attribute(attribute: "description", value: "Ktorrent insufficiently validated the target file name. A
malicious Server could therefore overwrite arbitary files
of the user (CVE-2007-1384,CVE-2007-1799). Another bug
could be exploited to crash Ktorrent (CVE-2007-1385).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch ktorrent-3057");
script_end_attributes();

script_cve_id("CVE-2007-1384", "CVE-2007-1799", "CVE-2007-1385");
script_summary(english: "Check for the ktorrent-3057 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ktorrent-2.0.3-30", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
