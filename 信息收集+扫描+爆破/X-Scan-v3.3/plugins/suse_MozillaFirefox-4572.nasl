
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
 script_id(27528);
 script_version ("$Revision: 1.4 $");
 script_name(english: "SuSE Security Update:  MozillaFirefox: Security update to version 2.0.0.8 (MozillaFirefox-4572)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaFirefox-4572");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Firefox to security update
version 2.0.0.8

Following security problems were fixed:
- MFSA 2007-26 / CVE-2007-3844: Privilege escalation
  through chrome-loaded about:blank windows

  Mozilla researcher moz_bug_r_a4 reported that a flaw was
introduced by the fix for MFSA 2007-20 that could enable
privilege escalation attacks against addons that create
'about:blank' windows and populate them in certain ways
(including implicit 'about:blank' document creation through
data: or javascript: URLs in a new window).

- MFSA 2007-29: Crashes with evidence of memory corruption
  As part of the Firefox 2.0.0.8 update releases Mozilla
  developers fixed many bugs to improve the stability of
  the product. Some of these crashes showed evidence of
  memory corruption under certain circumstances and we
  presume that with enough effort at least some of these
  could be exploited to run arbitrary code.

  - CVE-2007-5339 Browser crashes
  - CVE-2007-5340 JavaScript engine crashes

- MFSA 2007-30 / CVE-2007-1095: onUnload Tailgating

  Michal Zalewski demonstrated that onUnload event handlers
had access to the  address of the new page about to be
loaded, even if the navigation was triggered from outside
the page content such as by using a bookmark, pressing the
back button, or typing an address into the location bar. If
the bookmark contained sensitive information in the URL the
attacking page might be able to take advantage of it. An
attacking page would also be able to redirect the user,
perhaps to a phishing page that looked like the site the
user thought they were about to visit.


- MFSA 2007-31 / CVE-2007-2292: Digest authentication
  request splitting

  Security researcher Stefano Di Paola reported that
Firefox did not properly validate the user ID when making
an HTTP request using Digest Authentication to log into a
web site. A malicious page could abuse this to inject
arbitrary HTTP headers by including a newline character in
the user ID followed by the injected header data. If the
user were connecting through a proxy the attacker could
inject headers that a proxy would interpret as two separate
requests for different hosts.


- MFSA 2007-32 / CVE-2007-3511 / CVE-2006-2894: File input
  focus stealing vulnerability

  A user on the Sla.ckers.org forums named hong reported
that a file upload   control could be filled
programmatically by switching page focus to the label
before a file upload form control for selected keyboard
events. An attacker could use this trick to steal files
from the users' computer if the attacker knew the full
pathnames to the desired fileis and could create a pretext
that  would convince the user to type long enough to
produce all the necessary characters.


- MFSA 2007-33 / CVE-2007-5334: XUL pages can hide the
  window titlebar

  Mozilla developer Eli Friedman discovered that web pages
written in the XUL markup language (rather than the usual
HTML) can hide their window's titlebar. It may have been
possible to abuse this ablity to create more convincing
spoof and phishing pages.


- MFSA 2007-34 / CVE-2007-5337: Possible file stealing
  through sftp protocol

  On Linux machines with gnome-vfs support the smb: and
sftp: URI schemes are available in Firefox. Georgi Guninski
showed that if an attacker can store the attack page in a
mutually accessible location on the target server (/tmp
perhaps) and lure the victim into loading it, the attacker
could potentially read any file owned by the victim from
known locations on that server.


- MFSA 2007-35 / CVE-2007-5338: XPCNativeWraper pollution
  using Script object

  Mozilla security researcher moz_bug_r_a4 reported that it
was possible to use the Script object to modify
XPCNativeWrappers in such a way that subsequent    access
by the browser chrome--such as by right-clicking to open a
context menu--can cause attacker-supplied javascript to run
with the same privileges as the user. This is similar to
MFSA 2007-25 fixed in Firefox 2.0.0.5

Only Windows is affected by:

- MFSA 2007-27 / CVE-2007-3845: Unescaped URIs passed to
  external programs

  This problem affects Windows only due to their handling
of URI launchers. 

- MFSA 2007-28 / CVE-2006-4965: Code execution via
  QuickTime Media-link files

  Linux does not have .lnk files, nor Quicktime. Not
affected.

- MFSA 2007-36 / CVE-2007-4841 URIs with invalid %-encoding
  mishandled by Windows

  This problem does not affected Linux.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaFirefox-4572");
script_end_attributes();

script_cve_id("CVE-2007-3844", "CVE-2007-5339", "CVE-2007-5340", "CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2006-2894", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-3845", "CVE-2006-4965", "CVE-2007-4841");
script_summary(english: "Check for the MozillaFirefox-4572 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaFirefox-2.0.0.8-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-2.0.0.8-1.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
