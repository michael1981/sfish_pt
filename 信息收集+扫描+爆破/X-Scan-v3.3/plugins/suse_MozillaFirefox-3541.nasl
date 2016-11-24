
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27120);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  MozillaFirefox: Security update to version 2.0.0.4 (MozillaFirefox-3541)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaFirefox-3541");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Firefox to security update
version 2.0.0.4

This is a major upgrade from the Firefox 1.5.0.x line for
SUSE Linux 10.0.

- MFSA 2007-17 / CVE-2007-2871:

  Chris Thomas demonstrated that XUL popups opened by web
content could be placed outside the boundaries of the
content area. This could be used to spoof or hide parts of
the browser chrome such as the location bar.

- MFSA 2007-16 / CVE-2007-2870:

  Mozilla contributor moz_bug_r_a4 demonstrated that the
addEventListener method could be used to inject script into
another site in violation of the browser's same-origin
policy. This could be used to access or modify private or
valuable information from that other site.

- MFSA 2007-14 / CVE-2007-1362:

  Nicolas Derouet reported two problems with cookie
handling in Mozilla clients. Insufficient length checks
could be use to exhaust browser memory and so to crash the
browser or at least slow it done by a large degree.

  The second issue was that the cookie path and name values
were not checked for the presence of the delimiter used for
internal cookie storage, and if present this confused
future interpretation of the cookie data. This is not
considered to be exploitable.

- MFSA 2007-13 / CVE-2007-2869:

  Marcel reported that a malicious web page could perform a
denial of service attack against the form autocomplete
feature that would persist from session to session until
the malicious form data was deleted. Filling a text field
with millions of characters and submitting the form will
cause the victim's browser to hang for up to several
minutes while the form data is read, and this will happen
the first time autocomplete is triggered after every
browser restart. 

  No harm is done to the user's computer, but the
frustration caused by the hang could prevent use of Firefox
if users don't know how to clear the bad state.

- MFSA 2007-12 / CVE-2007-2867 / CVE-2007-2868

  As part of the Firefox 2.0.0.4 and 1.5.0.12 update
releases Mozilla developers fixed many bugs to improve the
stability of the product. Some of these crashes that showed
evidence of memory corruption under certain circumstances
and we presume that with enough effort at least some of
these could be exploited to run arbitrary code. 

  Without further investigation we cannot rule out the
possibility that for some of these an attacker might be
able to prepare memory for exploitation through some means
other than JavaScript, such as large images.

- MFSA 2007-11 / CVE-2007-1562:

  Incorrect FTP PASV handling could be used by malicious
ftp servers to do a rudimentary port scanning of for
instance internal networks of the computer the browser is
running on.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaFirefox-3541");
script_end_attributes();

script_cve_id("CVE-2007-2871", "CVE-2007-2870", "CVE-2007-1362", "CVE-2007-2869", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-1562");
script_summary(english: "Check for the MozillaFirefox-3541 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaFirefox-2.0.0.4-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-2.0.0.4-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
