
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32454);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  opensuse-updater: Fix for memory and symlink problem(s) (opensuse-updater-5262)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch opensuse-updater-5262");
 script_set_attribute(attribute: "description", value: "This update fixes a symlink problem and two off-by-one
vulnerabilities.  The overflows can be considered no
security problem but the symlink flaw could be used by
local users to gain unauthorized access to information
(like passwords).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch opensuse-updater-5262");
script_end_attributes();

script_summary(english: "Check for the opensuse-updater-5262 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"opensuse-updater-0.5-0.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
