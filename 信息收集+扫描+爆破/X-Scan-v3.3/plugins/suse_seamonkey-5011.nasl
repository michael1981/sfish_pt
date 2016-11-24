
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31113);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  seamonkey: Security update (seamonkey-5011)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch seamonkey-5011");
 script_set_attribute(attribute: "description", value: "This update backports changes to Mozilla Seamonkey to the
level of the security update version 1.8.1.12

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
- MFSA 2008-01/CVE-2008-0412/CVE-2008-0413 Crashes with
  evidence of memory corruption (rv:1.8.1.12)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch seamonkey-5011");
script_end_attributes();

script_cve_id("CVE-2008-0594", "CVE-2008-0593", "CVE-2008-0592", "CVE-2008-0591", "CVE-2008-0419", "CVE-2008-0418", "CVE-2008-0417", "CVE-2008-0415", "CVE-2008-0414", "CVE-2008-0412", "CVE-2008-0413");
script_summary(english: "Check for the seamonkey-5011 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"seamonkey-1.0.9-1.10", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-calendar-1.0.9-1.10", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.0.9-1.10", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-irc-1.0.9-1.10", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.0.9-1.10", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-spellchecker-1.0.9-1.10", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-venkman-1.0.9-1.10", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
