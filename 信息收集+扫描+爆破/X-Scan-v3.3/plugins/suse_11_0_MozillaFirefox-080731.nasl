
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39882);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  MozillaFirefox (2008-07-31)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for MozillaFirefox");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Firefox to version 3.0.1. It
fixes various bugs and also following security problems:

MFSA 2008-34 / CVE-2008-2785: An anonymous researcher, via
TippingPoint's Zero Day Initiative program, reported a
vulnerability in Mozilla CSS reference counting code. The
vulnerability was caused by an insufficiently sized
variable being used as a reference counter for CSS objects.
By creating a very large number of references to a common
CSS object, this counter could be overflowed which could
cause a crash when the browser attempts to free the CSS
object while still in use. An attacker could use this crash
to run arbitrary code on the victim's computer

MFSA 2008-35 / CVE-2008-2933: Security researcher Billy
Rios reported that if Firefox is not already running,
passing it a command-line URI with pipe symbols will open
multiple tabs. This URI splitting could be used to launch
privileged chrome: URIs from the command-line, a partial
bypass of the fix for MFSA 2005-53 which blocks external
applications from loading such URIs.

This vulnerability could also be used by an attacker to
launch a file: URI from the command line opening a
malicious local file which could exfiltrate data from the
local filesystem.

Combined with a vulnerability which allows an attacker to
inject code into a chrome document, the above issue could
be used to run arbitrary code on a victim's computer. Such
a chrome injection vulnerability was reported by Mozilla
developers Ben Turner and Dan Veditz who showed that a XUL
based SSL error page was not properly sanitizing inputs and
could be used to run arbitrary code with chrome privileges.

MFSA 2008-36 / CVE-2008-2934: Apple Security Researcher
Drew Yao reported a vulnerability in Mozilla graphics code
which handles GIF rendering in Mac OS X. He demonstrated
that a GIF file could be specially crafted to cause the
browser to free an uninitialized pointer. An attacker could
use this vulnerability to crash the browser and potentially
execute arbitrary code on the victim's computer.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for MozillaFirefox");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=407573");
script_end_attributes();

 script_cve_id("CVE-2008-2785", "CVE-2008-2933", "CVE-2008-2934");
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
if ( rpm_check( reference:"MozillaFirefox-3.0.1-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-3.0.1-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.0.1-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.0.1-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-1.9.0.1-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-1.9.0.1-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-32bit-1.9.0.1-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-devel-1.9.0.1-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-devel-1.9.0.1-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-1.9.0.1-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-1.9.0.1-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.1-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-1.9.0.1-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-1.9.0.1-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-32bit-1.9.0.1-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
