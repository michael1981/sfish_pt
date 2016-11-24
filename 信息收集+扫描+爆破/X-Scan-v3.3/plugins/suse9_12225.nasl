
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41234);
 script_version("$Revision: 1.2 $");
 script_name(english: "SuSE9 Security Update:  Security update for ethereal (12225)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12225");
 script_set_attribute(attribute: "description", value: 'Various vulnerabilities have been fixed in ethereal:
CVE-2008-3137, CVE-2008-3138, CVE-2008-3139,
CVE-2008-3140, CVE-2008-3141, CVE-2008-3145
and CVE-2008-3146.
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch 12225");
script_end_attributes();

script_cve_id("CVE-2008-3137","CVE-2008-3138","CVE-2008-3139","CVE-2008-3140","CVE-2008-3141","CVE-2008-3145","CVE-2008-3146");
script_summary(english: "Check for the security advisory #12225");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ethereal-0.10.13-2.34", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
