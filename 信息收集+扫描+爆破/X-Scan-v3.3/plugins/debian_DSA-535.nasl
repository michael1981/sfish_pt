# This script was automatically generated from the dsa-535
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15372);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "535");
 script_cve_id("CVE-2004-0519", "CVE-2004-0520", "CVE-2004-0521", "CVE-2004-0639");
 script_bugtraq_id(10246, 10439);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-535 security update');
 script_set_attribute(attribute: 'description', value:
'Four vulnerabilities were discovered in squirrelmail:
 Multiple cross-site scripting (XSS) vulnerabilities
 in SquirrelMail 1.4.2 allow remote attackers to execute arbitrary
 script as other users and possibly steal authentication information
 via multiple attack vectors, including the mailbox parameter in
 compose.php.
 Cross-site scripting (XSS) vulnerability in mime.php
 for SquirrelMail before 1.4.3 allows remote attackers to insert
 arbitrary HTML and script via the content-type mail header, as
 demonstrated using read_body.php.
 SQL injection vulnerability in SquirrelMail before
 1.4.3 RC1 allows remote attackers to execute unauthorized SQL
 statements, with unknown impact, probably via abook_database.php.
 Multiple cross-site scripting (XSS) vulnerabilities
 in Squirrelmail 1.2.10 and earlier allow remote attackers to inject
 arbitrary HTML or script via (1) the $mailer variable in
 read_body.php, (2) the $senderNames_part variable in
 mailbox_display.php, and possibly other vectors including (3) the
 $event_title variable or (4) the $event_text variable.
For the current stable distribution (woody), these problems have been
fixed in version 1:1.2.6-1.4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-535');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-535
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA535] DSA-535-1 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-535-1 squirrelmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-1.4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
