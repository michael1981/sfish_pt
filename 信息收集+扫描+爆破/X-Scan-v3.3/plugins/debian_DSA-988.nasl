# This script was automatically generated from the dsa-988
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22854);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "988");
 script_cve_id("CVE-2006-0188", "CVE-2006-0195", "CVE-2006-0377");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-988 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Squirrelmail, a
commonly used webmail system.  The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2006-0188
    Martijn Brinkers and Ben Maurer found a flaw in webmail.php that
    allows remote attackers to inject arbitrary web pages into the right
    frame via a URL in the right_frame parameter.
CVE-2006-0195
    Martijn Brinkers and Scott Hughes discovered an interpretation
    conflict in the MagicHTML filter that allows remote attackers to
    conduct cross-site scripting (XSS) attacks via style sheet
    specifiers with invalid (1) "/*" and "*/" comments, or (2) slashes
    inside the "url" keyword, which is processed by some web browsers
    including Internet Explorer.
CVE-2006-0377
    Vicente Aguilera of Internet Security Auditors, S.L. discovered a
    CRLF injection vulnerability, which allows remote attackers to
    inject arbitrary IMAP commands via newline characters in the mailbox
    parameter of the sqimap_mailbox_select command, aka "IMAP
    injection." There\'s no known way to exploit this yet.
For the old stable distribution (woody) these problems have been fixed in
version 1.2.6-5.
For the stable distribution (sarge) these problems have been fixed in
version 2:1.4.4-8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-988');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squirrelmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA988] DSA-988-1 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-988-1 squirrelmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-5');
deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-8');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
