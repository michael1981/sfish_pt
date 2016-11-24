
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(40404);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.1 Security Update:  MozillaFirefox (2009-07-24)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for MozillaFirefox");
 script_set_attribute(attribute: "description", value: "The MozillaFirefox 3.0.12 release fixes various bugs and
some critical security issues.

MFSA 2009-34 / CVE-2009-2462 / CVE-2009-2463 /
CVE-2009-2464 / CVE-2009-2465 / CVE-2009-2466:  Mozilla
developers and community members identified and fixed
several stability bugs in the browser engine used in
Firefox and other Mozilla-based products. Some of these
crashes showed evidence of memory corruption under certain
circumstances and we presume that with enough effort at
least some of these could be exploited to run arbitrary
code.

MFSA 2009-35 / CVE-2009-2467: Security researcher Attila
Suszter reported that when a page contains a Flash object
which presents a slow script dialog, and the page is
navigated while the dialog is still visible to the user,
the Flash plugin is unloaded resulting in a crash due to a
call to the deleted object. This crash could potentially be
used by an attacker to run arbitrary code on a victim's
computer.

MFSA 2009-36 / CVE-2009-1194:  oCERT security researcher
Will Drewry reported a series of heap and integer overflow
vulnerabilities which independently affected multiple font
glyph rendering libraries. On Linux platforms libpango was
susceptible to the vulnerabilities while on OS X
CoreGraphics was similarly vulnerable. An attacker could
trigger these overflows by constructing a very large text
run for the browser to display. Such an overflow can result
in a crash which the attacker could potentially use to run
arbitrary code on a victim's computer. The open-source
nature of Linux meant that Mozilla was able to work with
the libpango maintainers to implement the correct fix in
version 1.24 of that system library which was distributed
with OS security updates. On Mac OS X Firefox works around
the CoreGraphics flaw by limiting the length of text runs
passed to the system.

MFSA 2009-37 / CVE-2009-2469: Security researcher PenPal
reported a crash involving a SVG element on which a watch
function and __defineSetter__ function have been set for a
particular property. The crash showed evidence of memory
corruption and could potentially be used by an attacker to
run arbitrary code on a victim's computer.

MFSA 2009-39 / CVE-2009-2471: Mozilla developer Blake
Kaplan reported that setTimeout, when called with certain
object parameters which should be protected with a
XPCNativeWrapper, will fail to keep the object wrapped when
compiling the new function to be executed. If chrome
privileged code were to call setTimeout using this as an
argument, the this object will lose its wrapper and could
be unsafely accessed by chrome code. An attacker could use
such vulnerable code to run arbitrary JavaScript with
chrome privileges.

MFSA 2009-40 / CVE-2009-2472: Mozilla security researcher
moz_bug_r_a4 reported a series of vulnerabilities in which
objects that normally receive a XPCCrossOriginWrapper are
constructed without the wrapper. This can lead to cases
where JavaScript from one website may unsafely access
properties of such an object which had been set by a
different website. A malicious website could use this
vulnerability to launch a XSS attack and run arbitrary
JavaScript within the context of another site.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for MozillaFirefox");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=522109");
script_end_attributes();

 script_cve_id("CVE-2009-1194", "CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464", "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2467", "CVE-2009-2469", "CVE-2009-2471", "CVE-2009-2472");
script_summary(english: "Check for the MozillaFirefox package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaFirefox-3.0.12-0.1.2", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-3.0.12-0.1.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-branding-upstream-3.0.12-0.1.2", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-branding-upstream-3.0.12-0.1.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.0.12-0.1.2", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.0.12-0.1.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-32bit-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-devel-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-devel-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-32bit-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"python-xpcom190-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"python-xpcom190-1.9.0.12-1.1.1", release:"SUSE11.1", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
