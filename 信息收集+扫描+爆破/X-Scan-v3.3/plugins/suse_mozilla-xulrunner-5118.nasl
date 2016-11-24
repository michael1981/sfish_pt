
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31696);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for epiphany (mozilla-xulrunner-5118)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch mozilla-xulrunner-5118");
 script_set_attribute(attribute: "description", value: "This update of the Mozilla XULRunner engine catches up on
all previous security problems found in the XULRunner
engine.

Following security problems were fixed:
- MFSA 2008-11/CVE-2008-0594 Web forgery overwrite with div
  overlay
- MFSA 2008-10/CVE-2008-0593 URL token stealing via
  stylesheet redirect
- MFSA 2008-09/CVE-2008-0592 Mishandling of locally-saved
  plain text files
- MFSA 2008-08/CVE-2008-0591 File action dialog tampering
- MFSA 2008-06/CVE-2008-0419 Web browsing history and
  forward navigation stealing
- MFSA 2008-05/CVE-2008-0418 Directory traversal via
  chrome: URI
- MFSA 2008-04/CVE-2008-0417 Stored password corruption
- MFSA 2008-03/CVE-2008-0415 Privilege escalation, XSS,
  Remote Code Execution
- MFSA 2008-02/CVE-2008-0414 Multiple file input focus
  stealing vulnerabilities
- MFSA 2008-01/CVE-2008-0412 Crashes with evidence of
  memory corruption (rv:1.8.1.12)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch mozilla-xulrunner-5118");
script_end_attributes();

script_cve_id("CVE-2008-0412", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
script_summary(english: "Check for the mozilla-xulrunner-5118 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"mozilla-xulrunner-1.8.0.14eol-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"epiphany-1.8.5-14.5", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"epiphany-devel-1.8.5-14.5", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"epiphany-doc-1.8.5-14.5", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gecko-sdk-1.8.0.14eol-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner-1.8.0.14eol-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
