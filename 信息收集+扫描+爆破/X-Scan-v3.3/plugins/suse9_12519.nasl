
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42048);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for epiphany (12519)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12519");
 script_set_attribute(attribute: "description", value: 'This update brings the Mozilla Seamonkey Suite packages to the current stable
release 1.1.17.
Due to the major version update some incompatibilities might appear.
It fixes all currently published security issues, including but not limited to:
MFSA 2009-17/CVE-2009-1307: Same-origin violations when Adobe Flash loaded via view-source: scheme 
 
MFSA 2009-21/CVE-2009-1311:POST data sent to wrong site when saving web page with embedded frame 
 
MFSA 2009-24/CVE-2009-1392/CVE-2009-1832/CVE-2009-1833: Crashes with evidence of memory corruption (rv:1.9.0.11) 
 
MFSA 2009-26/CVE-2009-1835: Arbitrary domain cookie access by local file: resources 
 
MFSA 2009-27/CVE-2009-1836: SSL tampering via non-200 responses to proxy CONNECT requests 
 
MFSA 2009-29/CVE-2009-1838: Arbitrary code execution using event listeners attached to an element whose owner document is null 
 
MFSA 2009-32/CVE-2009-1841: JavaScript chrome privilege escalation 
MFSA 2009-33/CVE-2009-2210: Crash viewing multipart/alternative message with text/enhanced part
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch 12519");
script_end_attributes();

script_cve_id("CVE-2009-1307","CVE-2009-1311","CVE-2009-1392","CVE-2009-1832","CVE-2009-1833","CVE-2009-1835","CVE-2009-1836","CVE-2009-1838","CVE-2009-1841","CVE-2009-2210");
script_summary(english: "Check for the security advisory #12519");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"mozilla-1.8_seamonkey_1.1.17-0.6", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.8_seamonkey_1.1.17-0.6", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.8_seamonkey_1.1.17-0.6", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-irc-1.8_seamonkey_1.1.17-0.6", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.8_seamonkey_1.1.17-0.6", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-venkman-1.8_seamonkey_1.1.17-0.6", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
