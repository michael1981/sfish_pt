
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
 script_id(27442);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  seamonkey: Security update to version 1.1.2. (seamonkey-3632)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch seamonkey-3632");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Seamonkey to security update
version 1.1.2

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

- MFSA 2007-15 / CVE-2007-1558:

  Gaëtan Leurent informed us of a weakness in APOP
authentication that could allow an attacker to recover the
first part of your mail password if the attacker could
interpose a malicious mail server on your network
masquerading as your legitimate mail server. With normal
settings it could take several hours for the attacker to
gather enough data to recover just a few characters of the
password. This result was presented at the Fast Software
Encryption 2007 conference. 

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
frustration caused by the hang could prevent use of
Thunderbird if users don't know how to clear the bad state.

- MFSA 2007-12 / CVE-2007-2867 / CVE-2007-2868

  As part of the Thunderbird 2.0.0.4 and 1.5.0.12 update
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
script_set_attribute(attribute: "solution", value: "Install the security patch seamonkey-3632");
script_end_attributes();

script_cve_id("CVE-2007-2871", "CVE-2007-2870", "CVE-2007-1558", "CVE-2007-1362", "CVE-2007-2869", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-1562");
script_summary(english: "Check for the seamonkey-3632 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"seamonkey-1.1.2-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.1.2-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-irc-1.1.2-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.1.2-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-spellchecker-1.1.2-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-venkman-1.1.2-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
