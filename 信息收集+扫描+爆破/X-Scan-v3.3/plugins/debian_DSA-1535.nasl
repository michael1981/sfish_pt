# This script was automatically generated from the dsa-1535
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31806);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1535");
 script_cve_id("CVE-2007-4879", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1535 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Iceweasel
web browser, an unbranded version of the Firefox browser. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-4879
    Peter Brodersen and Alexander Klink discovered that the
    autoselection of SSL client certificates could lead to users
    being tracked, resulting in a loss of privacy.
CVE-2008-1233
    <q>moz_bug_r_a4</q> discovered that variants of CVE-2007-3738 and
    CVE-2007-5338 allow the execution of arbitrary code through
    XPCNativeWrapper.
CVE-2008-1234
    <q>moz_bug_r_a4</q> discovered that insecure handling of event
    handlers could lead to cross-site scripting.
CVE-2008-1235
    Boris Zbarsky, Johnny Stenback and <q>moz_bug_r_a4</q> discovered
    that incorrect principal handling could lead to cross-site
    scripting and the execution of arbitrary code.
CVE-2008-1236
    Tom Ferris, Seth Spitzer, Martin Wargers, John Daggett and Mats
    Palmgren discovered crashes in the layout engine, which might
    allow the execution of arbitrary code.
CVE-2008-1237
    <q>georgi</q>, <q>tgirmann</q> and Igor Bukanov discovered crashes in the
    Javascript engine, which might allow the execution of arbitrary
    code.
CVE-2008-1238
    Gregory Fleischer discovered that HTTP Referrer headers were
    handled incorrectly in combination with URLs containing Basic
    Authentication credentials with empty usernames, resulting
    in potential Cross-Site Request Forgery attacks.
CVE-2008-1240
    Gregory Fleischer discovered that web content fetched through
    the jar: protocol can use Java to connect to arbitrary ports.
    This is only an issue in combination with the non-free Java
    plugin.
CVE-2008-1241
    Chris Thomas discovered that background tabs could generate
    XUL popups overlaying the current tab, resulting in potential
    spoofing attacks.
The Mozilla products from the old stable distribution (sarge) are no
longer supported.
For the stable distribution (etch), these problems have been fixed in
version 2.0.0.13-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1535');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your iceweasel packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1535] DSA-1535-1 iceweasel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1535-1 iceweasel");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'firefox', release: '4.0', reference: '2.0.0.13-0etch1');
deb_check(prefix: 'firefox-dom-inspector', release: '4.0', reference: '2.0.0.13-0etch1');
deb_check(prefix: 'firefox-gnome-support', release: '4.0', reference: '2.0.0.13-0etch1');
deb_check(prefix: 'iceweasel', release: '4.0', reference: '2.0.0.13-0etch1');
deb_check(prefix: 'iceweasel-dbg', release: '4.0', reference: '2.0.0.13-0etch1');
deb_check(prefix: 'iceweasel-dom-inspector', release: '4.0', reference: '2.0.0.13-0etch1');
deb_check(prefix: 'iceweasel-gnome-support', release: '4.0', reference: '2.0.0.13-0etch1');
deb_check(prefix: 'mozilla-firefox', release: '4.0', reference: '2.0.0.13-0etch1');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '4.0', reference: '2.0.0.13-0etch1');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '4.0', reference: '2.0.0.13-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
