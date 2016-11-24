
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41079);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for arc (10496)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 10496");
 script_set_attribute(attribute: "description", value: 'This updates fixes two bugs:
* Eric Romang discovered that the ARC archive program
under Unix creates a temporary file with insecure
permissions which may lead to an attacker stealing
sensitive information (CVE-2005-2945).
* Joey Schulze discovered that the temporary file was
created in an insecure fashion as well, leaving it open
to a classic symlink attack (CVE-2005-2992).
');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch 10496");
script_end_attributes();

script_summary(english: "Check for the security advisory #10496");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"arc-5.21e-653.4", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
