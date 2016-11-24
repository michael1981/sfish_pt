
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29358);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for Mozilla Firefox (MozillaFirefox-2423)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaFirefox-2423");
 script_set_attribute(attribute: "description", value: "This update brings MozillaFirefox to the security update
release 1.5.0.9, 
 including the following security fixes.

http://www.mozilla.org/projects/security/known-vulnerabilities.html

CVE-2006-6497/MFSA2006-68: Crashes with evidence of memory
corruption were fixed in the layout engine.
CVE-2006-6498/MFSA2006-68: Crashes with evidence of memory
corruption were fixed in the javascript engine.
CVE-2006-6499/MFSA2006-68: Crashes regarding floating point
usage were fixed.
 CVE-2006-6500/MFSA2006-69: This issue
only affects Windows systems, Linux is not affected.
CVE-2006-6501/MFSA2006-70: A privilege escalation using a
watch point was fixed.
 CVE-2006-6502/MFSA2006-71: A
LiveConnect crash finalizing JS objects was fixed.
CVE-2006-6503/MFSA2006-72: A XSS problem caused by setting
img.src to javascript: URI was fixed.
CVE-2006-6504/MFSA2006-73: A Mozilla SVG Processing Remote
Code Execution was fixed.
 CVE-2006-6505/MFSA2006-74: Some
Mail header processing heap overflows were fixed.
CVE-2006-6506/MFSA2006-75: The RSS Feed-preview referrer
leak was fixed.
 CVE-2006-6507/MFSA2006-76: A XSS problem
using outer window's Function object was fixed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaFirefox-2423");
script_end_attributes();

script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6500", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504", "CVE-2006-6505", "CVE-2006-6506", "CVE-2006-6507");
script_summary(english: "Check for the MozillaFirefox-2423 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"MozillaFirefox-1.5.0.9-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.5.0.9-0.2", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-1.5.0.9-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-1.5.0.9-0.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
