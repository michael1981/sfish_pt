
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41090);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for gdm (11050)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 11050");
 script_set_attribute(attribute: "description", value: 'This update solves a bug in GDM. This bug allows to bypass
root authorization to access the login configuration.
(CVE-2006-2452)
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch 11050");
script_end_attributes();

script_cve_id("CVE-2006-2452");
script_summary(english: "Check for the security advisory #11050");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gdm-2.4.4.7-35.4", release:"SUSE9", cpu: "i586") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
