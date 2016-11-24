
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41078);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for zlib (10347)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 10347");
 script_set_attribute(attribute: "description", value: 'The previous zlib update for CVE-2005-2096 fixed a flaw in
zlib that could allow a carefully crafted compressed stream
to crash an application. While the original patch corrected
the reported overflow, Markus Oberhumer discovered
additional ways a stream could trigger an overflow.
This security update fixes this problem.
This issue is tracked by the Mitre CVE ID CVE-2005-1849.
');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Install the security patch 10347");
script_end_attributes();

script_summary(english: "Check for the security advisory #10347");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"zlib-1.2.1-70.12", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1-70.12", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
