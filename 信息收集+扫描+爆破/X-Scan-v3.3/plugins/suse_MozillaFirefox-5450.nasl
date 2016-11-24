
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33757);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for MozillaFirefox (MozillaFirefox-5450)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaFirefox-5450");
 script_set_attribute(attribute: "description", value: "MozillaFirefox was updated to version 2.0.0.16, which fixes
various bugs and following security issues:

MFSA 2008-34 CVE-2008-2785: An anonymous researcher, via
TippingPoint's Zero Day Initiative program, reported a
vulnerability in Mozilla CSS reference counting code. The
vulnerability was caused by an insufficiently sized
variable being used as a reference counter for CSS objects.
By creating a very large number of references to a common
CSS object, this counter could be overflowed which could
cause a crash when the browser attempts to free the CSS
object while still in use. An attacker could use this crash
to run arbitrary code on the victim's computer.

MFSA 2008-35 CVE-2008-2933: Security researcher Billy Rios
reported that if Firefox is not already running, passing it
a command-line URI with pipe symbols will open multiple
tabs. This URI splitting could be used to launch privileged
chrome: URIs from the command-line, a partial bypass of the
fix for MFSA 2005-53 which blocks external applications
from loading such URIs. This vulnerability could also be
used by an attacker to launch a file: URI from the command
line opening a malicious local file which could exfiltrate
data from the local filesystem. Combined with a
vulnerability which allows an attacker to inject code into
a chrome document, the above issue could be used to run
arbitrary code on a victim's computer. Such a chrome
injection vulnerability was reported by Mozilla developers
Ben Turner and Dan Veditz who showed that a XUL based SSL
error page was not properly sanitizing inputs and could be
used to run arbitrary code with chrome privileges.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaFirefox-5450");
script_end_attributes();

script_cve_id("CVE-2008-2785", "CVE-2008-2933");
script_summary(english: "Check for the MozillaFirefox-5450 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"MozillaFirefox-2.0.0.16-0.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-2.0.0.16-0.4", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-2.0.0.16-0.3.1", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-2.0.0.16-0.3.1", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-2.0.0.16-0.3.1", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-2.0.0.16-0.3.1", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
