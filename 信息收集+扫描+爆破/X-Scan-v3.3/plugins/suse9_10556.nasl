
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41083);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for libungif (10556)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 10556");
 script_set_attribute(attribute: "description", value: 'This update fixes the following security issues:
* specially crafted GIF files could crash applications
(CVE-2005-2974).
* specially crafted GIF files could overwrite memory which
potentially allowed to execute arbitrary code
(CVE-2005-3350).
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch 10556");
script_end_attributes();

script_cve_id("CVE-2005-2974","CVE-2005-3350");
script_summary(english: "Check for the security advisory #10556");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libungif-4.1.0b1-585.4", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
