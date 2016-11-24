
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41985);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  MozillaThunderbird: Update to 2.0.0.22 security release (MozillaThunderbird-6347)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaThunderbird-6347");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird was updated to the 2.0.0.22 security
release. It fixes various bugs and security issues:

  * MFSA-2009-14/CVE-2009-1302/CVE-2009-1303/CVE-2009-1304
    CVE-2009-1305 Crashes with evidence of memory
    corruption (rv:1.9.0.9)
  * MFSA 2009-17/CVE-2009-1307 (bmo#481342) Same-origin
    violations when Adobe Flash loaded via view-source:
    scheme
  * MFSA 2009-24/CVE-2009-1392/CVE-2009-1832/CVE-2009-1833
    Crashes with evidence of memory corruption (rv:1.9.0.11)
  * MFSA 2009-27/CVE-2009-1836 (bmo#479880) SSL tampering
    via non-200 responses to proxy CONNECT requests
  * MFSA 2009-29/CVE-2009-1838 (bmo#489131) Arbitrary code
    execution using event listeners attached to an element
    whose owner document is null
  * MFSA 2009-32/CVE-2009-1841 (bmo#479560) JavaScript
    chrome privilege escalation
  * MFSA 2009-33 (bmo#495057) Crash viewing
    multipart/alternative message with text/enhanced part
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaThunderbird-6347");
script_end_attributes();

script_cve_id("CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1307", "CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841");
script_summary(english: "Check for the MozillaThunderbird-6347 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-2.0.0.22-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-devel-2.0.0.22-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-2.0.0.22-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
