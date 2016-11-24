
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
 script_id(42363);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  MozillaFirefox (2009-10-30)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for MozillaFirefox");
 script_set_attribute(attribute: "description", value: "The Mozilla Firefox browser was updated to version 3.5.4 to
fix various bugs and security issues.

Following security issues have been fixed: MFSA 2009-52 /
CVE-2009-3370: Security researcher Paul Stone reported that
a user's form history, both from web content as well as the
smart location bar, was vulnerable to theft. A malicious
web page could synthesize events such as mouse focus and
key presses on behalf of the victim and trick the browser
into auto-filling the form fields with history entries and
then reading the entries.

MFSA 2009-53 / CVE-2009-3274: Security researcher Jeremy
Brown reported that the file naming scheme used for
downloading a file which already exists in the downloads
folder is predictable. If an attacker had local access to a
victim's computer and knew the name of a file the victim
intended to open through the Download Manager, he could use
this vulnerability to place a malicious file in the
world-writable directory used to save temporary downloaded
files and cause the browser to choose the incorrect file
when opening it. Since this attack requires local access to
the victim's machine, the severity of this vulnerability
was determined to be low.

MFSA 2009-54 / CVE-2009-3371: Security researcher Orlando
Berrera of Sec Theory reported that recursive creation of
JavaScript web-workers can be used to create a set of
objects whose memory could be freed prior to their use.
These conditions often result in a crash which could
potentially be used by an attacker to run arbitrary code on
a victim's computer.

MFSA 2009-55 / CVE-2009-3372: Security researcher Marco C.
reported a flaw in the parsing of regular expressions used
in Proxy Auto-configuration (PAC) files. In certain cases
this flaw could be used by an attacker to crash a victim's
browser and run arbitrary code on their computer. Since
this vulnerability requires the victim to have PAC
configured in their environment with specific regular
expresssions which can trigger the crash, the severity of
the issue was determined to be moderate.

MFSA 2009-56 / CVE-2009-3373: Security research firm
iDefense reported that researcher regenrecht discovered a
heap-based buffer overflow in Mozilla's GIF image parser.
This vulnerability could potentially be used by an attacker
to crash a victim's browser and run arbitrary code on their
computer.

MFSA 2009-57 / CVE-2009-3374: Mozilla security researcher
moz_bug_r_a4 reported that the XPCOM utility
XPCVariant::VariantDataToJS unwrapped doubly-wrapped
objects before returning them to chrome callers. This could
result in chrome privileged code calling methods on an
object which had previously been created or modified by web
content, potentially executing malicious JavaScript code
with chrome privileges.


MFSA 2009-59 / CVE-2009-1563: Security researcher Alin Rad
Pop of Secunia Research reported a heap-based buffer
overflow in Mozilla's string to floating point number
conversion routines. Using this vulnerability an attacker
could craft some malicious JavaScript code containing a
very long string to be converted to a floating point number
which would result in improper memory allocation and the
execution of an arbitrary memory location. This
vulnerability could thus be leveraged by the attacker to
run arbitrary code on a victim's computer.

MFSA 2009-61 / CVE-2009-3375: Security researcher Gregory
Fleischer reported that text within a selection on a web
page can be read by JavaScript in a different domain using
the document.getSelection function, violating the
same-origin policy. Since this vulnerability requires user
interaction to exploit, its severity was determined to be
moderate.


MFSA 2009-62 / CVE-2009-3376: Mozilla security researchers
Jesse Ruderman and Sid Stamm reported that when downloading
a file containing a right-to-left override character (RTL)
in the filename, the name displayed in the dialog title bar
conflicts with the name of the file shown in the dialog
body. An attacker could use this vulnerability to obfuscate
the name and file extension of a file to be downloaded and
opened, potentially causing a user to run an executable
file when they expected to open a non-executable file.

MFSA 2009-63 / CVE-2009-3377 / CVE-2009-3379 /
CVE-2009-3378 Mozilla upgraded several thirdparty libraries
used in media rendering to address multiple memory safety
and stability bugs identified by members of the Mozilla
community. Some of the bugs discovered could potentially be
used by an attacker to crash a victim's browser and execute
arbitrary code on their computer. liboggz, libvorbis, and
liboggplay were all upgraded to address these issues. Audio
and video capabilities were added in Firefox 3.5 so prior
releases of Firefox were not affected. Georgi Guninski
reported a crash in liboggz. (CVE-2009-3377), Lucas
Adamski, Matthew Gregan, David Keeler, and Dan Kaminsky
reported crashes in libvorbis. (CVE-2009-3379), Juan
Becerra reported a crash in liboggplay (CVE-2009-3378).

MFSA 2009-64 / CVE-2009-3380 / CVE-2009-3381 /
CVE-2009-3382 / CVE-2009-3383: Mozilla developers and
community members identified and fixed several stability
bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these crashes showed
evidence of memory corruption under certain circumstances
and we presume that with enough effort at least some of
these could be exploited to run arbitrary code.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for MozillaFirefox");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=545277");
script_end_attributes();

 script_cve_id("CVE-2009-1563", "CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3371", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3377", "CVE-2009-3378", "CVE-2009-3379", "CVE-2009-3380", "CVE-2009-3381", "CVE-2009-3382", "CVE-2009-3383");
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
if ( rpm_check( reference:"MozillaFirefox-3.5.4-1.1.2", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.5.4-1.1.2", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner191-1.9.1.4-2.1.3", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner191-gnomevfs-1.9.1.4-2.1.3", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner191-translations-1.9.1.4-2.1.3", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-3.5.4-1.1.2", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.5.4-1.1.2", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner191-1.9.1.4-2.1.3", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner191-gnomevfs-1.9.1.4-2.1.3", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner191-translations-1.9.1.4-2.1.3", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
