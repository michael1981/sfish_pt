
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41467);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  Security update for MozillaFirefox (MozillaFirefox-6187)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaFirefox-6187");
 script_set_attribute(attribute: "description", value: "The Mozilla Firefox Browser was refreshed to the current
MOZILLA_1_8 branch state around fix level 2.0.0.22. 

Security issues identified as being fixed are: MFSA 2009-01
/ CVE-2009-0352 / CVE-2009-0353: Mozilla developers
identified and fixed several stability bugs in the browser
engine used in Firefox and other Mozilla-based products.
Some of these crashes showed evidence of memory corruption
under certain circumstances and we presume that with enough
effort at least some of these could be exploited to run
arbitrary code.

MFSA 2009-07 / CVE-2009-0772 / CVE-2009-0774: Mozilla
developers identified and fixed several stability bugs in
the browser engine used in Firefox and other Mozilla-based
products. Some of these crashes showed evidence of memory
corruption under certain circumstances and we presume that
with enough effort at least some of these could be
exploited to run arbitrary code.

MFSA 2009-09 / CVE-2009-0776: Mozilla security researcher
Georgi Guninski reported that a website could use
nsIRDFService and a cross-domain redirect to steal
arbitrary XML data from another domain, a violation of the
same-origin policy. This vulnerability could be used by a
malicious website to steal private data from users
authenticated to the redirected website.

MFSA 2009-10 / CVE-2009-0040: Google security researcher
Tavis Ormandy reported several memory safety hazards to the
libpng project, an external library used by Mozilla to
render PNG images. These vulnerabilities could be used by a
malicious website to crash a victim's browser and
potentially execute arbitrary code on their computer.
libpng was upgraded to version 1.2.35 which containis fixes
for these flaws.

MFSA 2009-12 / CVE-2009-1169: Security researcher Guido
Landi discovered that a XSL stylesheet could be used to
crash the browser during a XSL transformation. An attacker
could potentially use this crash to run arbitrary code on a
victim's computer. This vulnerability was also previously
reported as a stability problem by Ubuntu community member,
Andre. Ubuntu community member Michael Rooney reported
Andre's findings to Mozilla, and Mozilla community member
Martin helped reduce Andre's original testcase and
contributed a patch to fix the vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaFirefox-6187");
script_end_attributes();

script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0772", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-1169");
script_summary(english: "Check for the MozillaFirefox-6187 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"MozillaFirefox-2.0.0.21post-0.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-2.0.0.21post-0.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
