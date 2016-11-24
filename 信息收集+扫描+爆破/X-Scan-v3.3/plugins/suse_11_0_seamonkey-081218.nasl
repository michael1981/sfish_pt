
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
 script_id(40132);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.0 Security Update:  seamonkey (2008-12-18)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for seamonkey");
 script_set_attribute(attribute: "description", value: "The Mozilla Seamonkey browser suite was updated to version
1.1.14.

The following security issues were fixed:

MFSA 2008-68 / CVE-2008-5512 / CVE-2008-5511: Mozilla
security researcher moz_bug_r_a4 reported that an XBL
binding, when attached to an unloaded document, can be used
to violate the same-origin policy and execute arbitrary
JavaScript within the context of a different website.
moz_bug_r_a4 also reported two vulnerabilities by which
page content can pollute XPCNativeWrappers and run arbitary
JavaScript with chrome priviliges. Thunderbird shares the
browser engine with Firefox and could be vulnerable if
JavaScript were to be enabled in mail. This is not the
default setting and we strongly discourage users from
running JavaScript in mail. Workaround Disable JavaScript
until a version containing these fixes can be installed.

MFSA 2008-67 / CVE-2008-5510: Kojima Hajime reported that
unlike literal null characters which were handled
correctly, the escaped form '\0' was ignored by the CSS
parser and treated as if it was not present in the CSS
input string. This issue could potentially be used to
bypass script sanitization routines in web applications.
The severity of this issue was determined to be low.


MFSA 2008-66 / CVE-2008-5508: Perl developer Chip
Salzenberg reported that certain control characters, when
placed at the beginning of a URL, would lead to incorrect
parsing resulting in a malformed URL being output by the
parser. IBM researchers Justin Schuh, Tom Cross, and Peter
William also reported a related symptom as part of their
research that resulted in MFSA 2008-37.  There was no
direct security impact from this issue and its effect was
limited to the improper rendering of hyperlinks containing
specific characters. The severity of this issue was
determined to be low.


MFSA 2008-65 / CVE-2008-5507: Google security researcher
Chris Evans reported that a website could access a limited
amount of data from a different domain by loading a
same-domain JavaScript URL which redirects to an off-domain
target resource containing data which is not parsable as
JavaScript. Upon attempting to load the data as JavaScript
a syntax error is generated that can reveal some of the
file context via the window.onerror DOM API. This issue
could be used by a malicious website to steal private data
from users who are authenticated on the redirected website.
How much data could be at risk would depend on the format
of the data and how the JavaScript parser attempts to
interpret it. For most files the amount of data that can be
recovered would be limited to the first word or two. Some
data files might allow deeper probing with repeated loads.
Thunderbird shares the browser engine with Firefox and
could be vulnerable if JavaScript were to be enabled in
mail. This is not the default setting and we strongly
discourage users from running JavaScript in mail.
Workaround Disable JavaScript until a version containing
these fixes can be installed.

MFSA 2008-64 / CVE-2008-5506: Marius Schilder of Google
Security reported that when a XMLHttpRequest is made to a
same-origin resource which 302 redirects to a resource in a
different domain, the response from the cross-domain
resource is readable by the site issuing the XHR. Cookies
marked HttpOnly were not readable, but other potentially
sensitive data could be revealed in the XHR response
including URL parameters and content in the response body.
Thunderbird shares the browser engine with Firefox and
could be vulnerable if JavaScript were to be enabled in
mail. This is not the default setting and we strongly
discourage users from running JavaScript in mail.
Workaround Disable JavaScript until a version containing
these fixes can be installed.

MFSA 2008-61 / CVE-2008-5503: Mozilla developer Boris
Zbarsky reported that XBL bindings could be used to read
data from other domains, a violation of the same-origin
policy. The severity of this issue was determined to be
moderate due to several mitigating factors: The target
document requires a <bindingsi> element in the XBL
namespace in order to be read. The reader of the data needs
to know the id attribute of the binding being read in
advance. It is unlikely that web services will expose
private data in the manner described above. Firefox 3 is
not affected by this issue. Thunderbird shares the browser
engine with Firefox and could be vulnerable if JavaScript
were to be enabled in mail. This is not the default setting
and we strongly discourage users from running JavaScript in
mail. Workaround Products built from the Mozilla 1.9.0
branch and later, Firefox 3 for example, are not affected
by this issue. Upgrading to one of these products is a
reliable workaround for this particular issue and it is
also Mozilla's recommendation that the most current version
of any Mozilla product be used. Alternatively, you can
disable JavaScript until a version containing these fixes
can be installed.

MFSA 2008-60 / CVE-2008-5500: Mozilla developers identified
and fixed several stability bugs in the browser engine used
in Firefox and other Mozilla-based products. Some of these
crashes showed evidence of memory corruption under certain
circumstances and we presume that with enough effort at
least some of these could be exploited to run arbitrary
code. Thunderbird shares the browser engine with Firefox
and could be vulnerable if JavaScript were to be enabled in
mail. This is not the default setting and we strongly
discourage users from running JavaScript in mail. Without
further investigation we cannot rule out the possibility
that for some of these an attacker might be able to prepare
memory for exploitation through some means other than
JavaScript such as large images. Workaround Disable
JavaScript until a version containing these fixes can be
installed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for seamonkey");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=455804");
script_end_attributes();

 script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512");
script_summary(english: "Check for the seamonkey package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"seamonkey-1.1.14-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-1.1.14-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.1.14-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.1.14-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-irc-1.1.14-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-irc-1.1.14-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.1.14-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.1.14-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-spellchecker-1.1.14-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-spellchecker-1.1.14-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-venkman-1.1.14-0.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"seamonkey-venkman-1.1.14-0.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
