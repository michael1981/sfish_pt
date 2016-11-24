
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
 script_id(39886);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.0 Security Update:  MozillaFirefox (2009-02-06)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for MozillaFirefox");
 script_set_attribute(attribute: "description", value: "The Mozilla Firefox browser is updated to version 3.0.6
fixing various security and stability issues.

MFSA 2009-01 / CVE-2009-0352 / CVE-2009-0353: Mozilla
developers identified and fixed several stability bugs in
the browser engine used in Firefox and other Mozilla-based
products. Some of these crashes showed evidence of memory
corruption under certain circumstances and we presume that
with enough effort at least some of these could be
exploited to run arbitrary code.

MFSA 2009-02 / CVE-2009-0354: Mozilla security researcher
moz_bug_r_a4 reported that a chrome XBL method can be used
in conjuction with window.eval to execute arbitrary
JavaScript within the context of another website, violating
the same origin policy. Firefox 2 releases are not affected.

MFSA 2009-03 / CVE-2009-0355: Mozilla security researcher
moz_bug_r_a4 reported that a form input control's type
could be changed during the restoration of a closed tab. An
attacker could set an input control's text value to the
path of a local file whose location was known to the
attacker. If the tab was then closed and the victim
persuaded to re-open it, upon restoring the tab the
attacker could use this vulnerability to change the input
type to file. Scripts in the page could then automatically
submit the form and steal the contents of the user's local
file.

MFSA 2009-04 / CVE-2009-0356: Mozilla security researcher
Georgi Guninski reported that the fix for an earlier
vulnerability reported by Liu Die Yu using local internet
shortcut files to access other sites (MFSA 2008-47) could
be bypassed by redirecting to a privileged about: URI such
as about:plugins. If an attacker could get a victim to
download two files, a malicious HTML file and a .desktop
shortcut file, they could have the HTML document load a
privileged chrome document via the shortcut and both
documents would be treated as same origin. This
vulnerability could potentially be used by an attacker to
inject arbitrary code into the chrome document and execute
with chrome privileges. Because this attack has relatively
high complexity, the severity of this issue was determined
to be moderate.

MFSA 2009-05 / CVE-2009-0357: Developer and Mozilla
community member Wladimir Palant reported that cookies
marked HTTPOnly were readable by JavaScript via the
XMLHttpRequest.getResponseHeader and
XMLHttpRequest.getAllResponseHeaders APIs. This
vulnerability bypasses the security mechanism provided by
the HTTPOnly flag which intends to restrict JavaScript
access to document.cookie. The fix prevents the
XMLHttpRequest feature from accessing the Set-Cookie and
Set-Cookie2 headers of any response whether or not the
HTTPOnly flag was set for those cookies.

MFSA 2009-06 / CVE-2009-0358: Paul Nel reported that
certain HTTP directives to not cache web pages,
Cache-Control: no-store and Cache-Control: no-cache for
HTTPS pages, were being ignored by Firefox 3. On a shared
system, applications relying upon these HTTP directives
could potentially expose private data. Another user on the
system could use this vulnerability to view improperly
cached pages containing private data by navigating the
browser back.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for MozillaFirefox");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=470074");
script_end_attributes();

 script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");
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
if ( rpm_check( reference:"MozillaFirefox-3.0.6-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-3.0.6-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.0.6-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-3.0.6-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-1.9.0.6-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-1.9.0.6-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-32bit-1.9.0.6-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-devel-1.9.0.6-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-devel-1.9.0.6-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-1.9.0.6-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-1.9.0.6-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.6-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-1.9.0.6-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-1.9.0.6-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner190-translations-32bit-1.9.0.6-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
