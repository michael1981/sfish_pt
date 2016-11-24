
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31602);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  MozillaThunderbird 2.0.0.12 security version upgrade (MozillaThunderbird-5098)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaThunderbird-5098");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Thunderbird to security update
version 2.0.0.12

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
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaThunderbird-5098");
script_end_attributes();

script_cve_id("CVE-2008-0594", "CVE-2008-0593", "CVE-2008-0592", "CVE-2008-0591", "CVE-2008-0419", "CVE-2008-0418", "CVE-2008-0417", "CVE-2008-0415", "CVE-2008-0414", "CVE-2008-0412");
script_summary(english: "Check for the MozillaThunderbird-5098 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-2.0.0.12-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-2.0.0.12-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
