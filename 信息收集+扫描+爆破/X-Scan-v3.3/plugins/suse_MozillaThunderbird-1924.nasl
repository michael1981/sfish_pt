
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(27125);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  MozillaThunderbird: Security update to version 1.5.0.6 (MozillaThunderbird-1924)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaThunderbird-1924");
 script_set_attribute(attribute: "description", value: "This security update brings Mozilla Thunderbird to version
1.5.0.6.

Note that on SUSE Linux 9.2, 9.3 and 10.0 this is a major
version upgrade.

More Details can be found on this page:
http://www.mozilla.org/projects/security/known-vulnerabiliti
es.html

It includes fixes to the following security problems:
- CVE-2006-3801/MFSA 2006-44: Code execution through
  deleted frame reference

  Thilo Girmann discovered that in certain circumstances a
JavaScript reference to a frame or window was not properly
cleared when the referenced content went away, and he
demonstrated that this pointer to a deleted object could be
used to execute native code supplied by the attacker.

- CVE-2006-3113/MFSA 2006-46: Memory corruption with
  simultaneous events

  Secunia Research has discovered a vulnerability in
Mozilla Firefox 1.5 branch, which can be exploited by
malicious people to compromise a user's system.

  The vulnerability is caused due to an memory corruption
error within the handling of simultaneously happening XPCOM
events, which leads to use of a deleted timer object. This
generally results in a crash but potentially could be
exploited to execute arbitrary code on a user's system when
a malicious website is visited.

- CVE-2006-3802/MFSA 2006-47: Native DOM methods can be
  hijacked across domains

  A malicious page can hijack native DOM methods on a
document object in another domain, which will run the
attacker's script when called by the victim page.  This
could be used to steal login cookies, password, or other
sensitive data on the target page, or to perform actions on
behalf of a logged-in user.

  Access checks on all other properties and document nodes
are performed correctly. This cross-site scripting (XSS)
attack is limited to pages which use standard DOM methods
of the top-level document object, such as
document.getElementById(). This includes many popular
sites, especially the newer ones that offer rich
interaction to the user.

- CVE-2006-3803/MFSA 2006-48: JavaScript new Function race
  condition

  H. D. Moore reported a testcase that was able to trigger
a race condition where JavaScript garbage collection
deleted a temporary variable still being used in the
creation of a new Function object. The resulting use of a
deleted object may be potentially exploitable to run native
code provided by the attacker.

- CVE-2006-3804/MFSA 2006-49: Heap buffer overwrite on
  malformed VCard

  A VCard attachment with a malformed base64 field (such as
a photo) can trigger a heap buffer overwrite. These have
proven exploitable in the past, though in this case the
overwrite is accompanied by an integer underflow that would
attempt to copy more data than the typical machine has,
leading to a crash.

- CVE-2006-3805/CVE-2006-3806/MFSA 2006-50: JavaScript
  engine vulnerabilities

  Continuing our security audit of the JavaScript engine,
Mozilla developers found and fixed several potential
vulnerabilities.

  Igor Bukanov and shutdown found additional places where
an untimely garbage collection could delete a temporary
object that was in active use (similar to MFSA 2006-01 and
MFSA 2006-10). Some of these may allow an attacker to run
arbitrary code given the right conditions.

  Georgi Guninski found potential integer overflow issues
with long strings in the toSource() methods of the Object,
Array and String objects as well as string function
arguments.

- CVE-2006-3807/MFSA 2006-51: Privilege escalation using
  named-functions and redefined 'new Object()'

  moz_bug_r_a4 discovered that named JavaScript functions
have a parent object created using the standard Object()
constructor (ECMA-specified behavior) and that this
constructor can be redefined by script (also ECMA-specified
behavior). If the Object() constructor is changed to return
a reference to a privileged object with useful properties
it is possible to have attacker-supplied script excuted
with elevated privileges by calling the function. This
could be used to install malware or take other malicious
actions.

  Our fix involves calling the internal Object constructor
which appears to be what other ECMA-compatible interpreters
do.

- CVE-2006-3808/MFSA 2006-52: PAC privilege escalation
  using Function.prototype.call

  moz_bug_r_a4 reports that a malicious Proxy AutoConfig
(PAC) server could serve a PAC script that can execute code
with elevated privileges by setting the required
FindProxyForURL function to the eval method on a privileged
object that leaked into the PAC sandbox. By redirecting the
victim to a specially-crafted URL -- easily done since the
PAC script controls which proxy to use -- the URL
'hostname' can be executed as privileged script.

  A malicious proxy server can perform spoofing attacks on
the user so it was already important to use a trustworthy
PAC server.

- CVE-2006-3809/MFSA 2006-53: UniversalBrowserRead
  privilege escalation

  shutdown reports that scripts granted the
UniversalBrowserRead privilege can leverage that into the
equivalent of the far more powerful UniversalXPConnect
since they are allowed to 'read' into a privileged context.
This allows the attacker the ability to run scripts with
the full privelege of the user running the browser,
possibly installing malware or snooping on private data.
This has been fixed so that UniversalBrowserRead and
UniversalBrowserWrite are limited to reading from and
writing into only normally-privileged browser windows and
frames.

- CVE-2006-3810/MFSA 2006-54: XSS with
  XPCNativeWrapper(window).Function(...)

  shutdown reports that cross-site scripting (XSS) attacks
could be performed using the construct
XPCNativeWrapper(window).Function(...), which created a
function that appeared to belong to the window in question
even after it had been navigated to the target site.

- CVE-2006-3811/MFSA 2006-55: Crashes with evidence of
  memory corruption

  As part of the Firefox 1.5.0.5 stability and security
release, developers in the Mozilla community looked for and
fixed several crash bugs to improve the stability of
Mozilla clients. Some of these crashes showed evidence of
memory corruption that we presume could be exploited to run
arbitrary code with enough effort.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaThunderbird-1924");
script_end_attributes();

script_cve_id("CVE-2006-3801", "CVE-2006-3113", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811");
script_summary(english: "Check for the MozillaThunderbird-1924 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.5-0.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-1.5.0.5-0.1", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
