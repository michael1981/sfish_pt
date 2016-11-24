
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39887);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.0 Security Update:  MozillaFirefox (2009-03-12)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for MozillaFirefox");
 script_set_attribute(attribute: "description", value: "The Mozilla Firefox browser is updated to version 3.0.7
fixing various security and stability issues.

MFSA 2009-07 / CVE-2009-0771 / CVE-2009-0772 /
CVE-2009-0773 / CVE-2009-0774: Mozilla developers
identified and fixed several stability bugs in the browser
engine used in Firefox and other Mozilla-based products.
Some of these crashes showed evidence of memory corruption
under certain circumstances and we presume that with enough
effort at least some of these could be exploited to run
arbitrary code.

MFSA 2009-08 / CVE-2009-0775: An anonymous researcher, via
TippingPoint's Zero Day Initiative program, reported a
vulnerability in Mozilla's garbage collection process. The
vulnerability was caused by improper memory management of a
set of cloned XUL DOM elements which were linked as a
parent and child. After reloading the browser on a page
with such linked elements, the browser would crash when
attempting to access an object which was already destroyed.
An attacker could use this crash to run arbitrary code on
the victim's computer.

MFSA 2009-09 / CVE-2009-0776: Mozilla security researcher
Georgi Guninski reported that a website could use
nsIRDFService and a cross-domain redirect to steal
arbitrary XML data from another domain, a violation of the
same-origin policy. This vulnerability could be used by a
malicious website to steal private data from users
authenticated to the redirected website.

MFSA 2009-10 / CVE-2009-0040: libpng maintainer Glenn
Randers-Pehrson reported several memory safety hazards in
PNG libraries used by Mozilla. These vulnerabilities could
be used by a malicious website to crash a victim's browser
and potentially execute arbitrary code on their computer.
libpng was upgraded to a version which contained fixes for
these flaws.

MFSA 2009-11 / CVE-2009-0777: Mozilla contributor Masahiro
Yamada reported that certain invisible control characters
were being decoded when displayed in the location bar,
resulting in fewer visible characters than were present in
the actual location. An attacker could use this
vulnerability to spoof the location bar and display a
misleading URL for their malicious web page.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for MozillaFirefox");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=478625");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=465284");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=479610");
script_end_attributes();

 script_cve_id("CVE-2009-0040", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777");
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
if ( rpm_check( reference:"MozillaFirefox-3.0.7-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-3.0.7-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.0.7-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.0.7-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-1.9.0.7-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-1.9.0.7-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-32bit-1.9.0.7-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-devel-1.9.0.7-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-devel-1.9.0.7-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-1.9.0.7-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-1.9.0.7-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.7-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-1.9.0.7-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-1.9.0.7-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-32bit-1.9.0.7-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
