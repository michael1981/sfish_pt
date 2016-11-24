
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41347);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for enscript (9867)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 9867");
 script_set_attribute(attribute: "description", value: '* Unsanitised input can caues the execution of arbitrary
commands via EPSF pipe support. This has been disabled,
also upstream ( CVE-2004-1184).
* Due to missing sanitising of filenames it is possible
that a specially crafted filename can cause arbitrary
commands to be executed ( CVE-2004-1185).
* Multiple buffer overflows can cause the program to crash
( CVE-2004-1186).
');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch 9867");
script_end_attributes();

script_summary(english: "Check for the security advisory #9867");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"enscript-1.6.2-814.6", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
