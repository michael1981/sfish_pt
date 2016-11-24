
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36006);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  imp security update (imp-6101)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch imp-6101");
 script_set_attribute(attribute: "description", value: "Version update to IMP 4.1.6 fixes a problem with validating
HTTP requests that allowed attackers to delete emails
(CVE-2007-6018) and some cross-site-scripting issues
(CVE-2009-0930).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch imp-6101");
script_end_attributes();

script_cve_id("CVE-2007-6018", "CVE-2009-0930");
script_summary(english: "Check for the imp-6101 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"imp-4.1.6-0.1", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
