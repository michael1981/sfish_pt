
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27340);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  lighttpd: security update (lighttpd-3985)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch lighttpd-3985");
 script_set_attribute(attribute: "description", value: "Multiple bugs in lighttpd allowed remote attackers to crash
lighttpd, circumvent access restricions or even execute
code. (CVE-2007-3946, CVE-2007-3947, CVE-2007-3948,
CVE-2007-3949, CVE-2007-3950)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch lighttpd-3985");
script_end_attributes();

script_cve_id("CVE-2007-3946", "CVE-2007-3947", "CVE-2007-3948", "CVE-2007-3949", "CVE-2007-3950");
script_summary(english: "Check for the lighttpd-3985 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"lighttpd-1.4.13-41.4", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
