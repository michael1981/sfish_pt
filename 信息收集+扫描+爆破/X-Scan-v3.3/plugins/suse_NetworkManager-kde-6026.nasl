
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41471);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for knetworkmanager (NetworkManager-kde-6026)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch NetworkManager-kde-6026");
 script_set_attribute(attribute: "description", value: "The knetworkmanager configuration was too permissive and
allowed any user to read secrets (CVE-2009-0365).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch NetworkManager-kde-6026");
script_end_attributes();

script_cve_id("CVE-2009-0365");
script_summary(english: "Check for the NetworkManager-kde-6026 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"NetworkManager-kde-0.1r588481-1.24", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
