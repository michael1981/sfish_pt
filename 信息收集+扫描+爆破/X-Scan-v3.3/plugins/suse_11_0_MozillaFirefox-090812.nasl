
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40641);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE 11.0 Security Update:  MozillaFirefox (2009-08-12)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for MozillaFirefox");
 script_set_attribute(attribute: "description", value: "MozillaFirefox was updated to the 3.0.13 release, fixing
some security issues and bugs:

MFSA 2009-44 / CVE-2009-2654: Security researcher Juan
Pablo Lopez Yacubian reported that an attacker could call
window.open() on an invalid URL which looks similar to a
legitimate URL and then use document.write() to place
content within the new document, appearing to have come
from the spoofed location. Additionally, if the spoofed
document was created by a document with a valid SSL
certificate, the SSL indicators would be carried over into
the spoofed document. An attacker could use these issues to
display misleading location and SSL information for a
malicious web page.

MFSA 2009-45 / CVE-2009-2662:The browser engine in Mozilla
Firefox before 3.0.13, and 3.5.x before 3.5.2, allows
remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute
arbitrary code via vectors related to the
TraceRecorder::snapshot function in js/src/jstracer.cpp,
and unspecified other vectors.

CVE-2009-2663 / MFSA 2009-45: libvorbis before r16182, as
used in Mozilla Firefox before 3.0.13 and 3.5.x before
3.5.2 and other products, allows context-dependent
attackers to cause a denial of service (memory corruption
and application crash) or possibly execute arbitrary code
via a crafted .ogg file.

CVE-2009-2664 / MFSA 2009-45: The js_watch_set function in
js/src/jsdbgapi.cpp in the JavaScript engine in Mozilla
Firefox before 3.0.13, and 3.5.x before 3.5.2, allows
remote attackers to cause a denial of service (assertion
failure and application exit) or possibly execute arbitrary
code via a crafted .js file, related to a 'memory safety
bug.'
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for MozillaFirefox");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=527489");
script_end_attributes();

 script_cve_id("CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664");
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
if ( rpm_check( reference:"MozillaFirefox-3.0.13-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-3.0.13-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.0.13-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.0.13-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gconf2-2.22.0-28.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gconf2-2.22.0-28.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"gconf2-32bit-2.22.0-28.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libidl-0.8.10-27.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libidl-0.8.10-27.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libidl-32bit-0.8.10-27.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-1.9.0.13-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-1.9.0.13-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-32bit-1.9.0.13-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-devel-1.9.0.13-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-devel-1.9.0.13-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-1.9.0.13-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-1.9.0.13-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.13-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-1.9.0.13-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-1.9.0.13-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-32bit-1.9.0.13-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"orbit2-2.14.12-32.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"orbit2-2.14.12-32.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"orbit2-32bit-2.14.12-32.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
