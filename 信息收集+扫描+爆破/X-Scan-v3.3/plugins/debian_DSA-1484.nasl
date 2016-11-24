# This script was automatically generated from the dsa-1484
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30224);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "1484");
 script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1484 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2008-0412
    Jesse Ruderman, Kai Engert, Martijn Wargers, Mats Palmgren and Paul
    Nickerson discovered crashes in the layout engine, which might allow
    the execution of arbitrary code.
CVE-2008-0413
    Carsten Book, Wesley Garland, Igor Bukanov, <q>moz_bug_r_a4</q>, <q>shutdown</q>,
    Philip Taylor and <q>tgirmann</q> discovered crashes in the JavaScript
    engine, which might allow the execution of arbitrary code.
CVE-2008-0414
    <q>hong</q> and Gregory Fleischer discovered that file input focus
    vulnerabilities in the file upload control could allow information
    disclosure of local files.
CVE-2008-0415
    <q>moz_bug_r_a4</q> and Boris Zbarsky discovered several
    vulnerabilities in JavaScript handling, which could allow
    privilege escalation.
CVE-2008-0417
    Justin Dolske discovered that the password storage mechanism could
    be abused by malicious web sites to corrupt existing saved passwords.
CVE-2008-0418
    Gerry Eisenhaur and <q>moz_bug_r_a4</q> discovered that a directory
    traversal vulnerability in chrome: URI handling could lead to
    information disclosure.
CVE-2008-0419
    David Bloom discovered a race condition in the image handling of
    designMode elements, which could lead to information disclosure or
    potentially the execution of arbitrary code.
CVE-2008-0591
    Michal Zalewski discovered that timers protecting security-sensitive
    dialogs (which disable dialog elements until a timeout is reached)
    could be bypassed by window focus changes through JavaScript.
CVE-2008-0592
    It was discovered that malformed content declarations of saved
    attachments could prevent a user from opening local files
    with a <q>.txt</q> file name, resulting in minor denial of service.
CVE-2008-0593
    Martin Straka discovered that insecure stylesheet handling during
    redirects could lead to information disclosure.
CVE-2008-0594
    Emil Ljungdahl and Lars-Olof Moilanen discovered that phishing
    protections could be bypassed with <div> elements.
The old stable distribution (sarge) doesn\'t contain xulrunner.
For the stable distribution (etch), these problems have been fixed in
version 1.8.0.15~pre080131b-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1484');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xulrunner packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1484] DSA-1484-1 xulrunner");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1484-1 xulrunner");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
