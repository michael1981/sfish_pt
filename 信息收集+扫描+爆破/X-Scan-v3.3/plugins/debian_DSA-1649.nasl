# This script was automatically generated from the dsa-1649
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34371);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1649");
 script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1649 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Iceweasel web
browser, an unbranded version of the Firefox browser. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2008-0016
   Justin Schuh, Tom Cross and Peter Williams discovered a buffer
   overflow in the parser for UTF-8 URLs, which may lead to the
   execution of arbitrary code.
CVE-2008-3835
   <q>moz_bug_r_a4</q> discovered that the same-origin check in
   nsXMLDocument::OnChannelRedirect() could by bypassed.
CVE-2008-3836
   <q>moz_bug_r_a4</q> discovered that several vulnerabilities in
   feedWriter could lead to Chrome privilege escalation.
CVE-2008-3837
   Paul Nickerson discovered that an attacker could move windows
   during a mouse click, resulting in unwanted action triggered by
   drag-and-drop.
CVE-2008-4058
   <q>moz_bug_r_a4</q> discovered a vulnerability which can result in
   Chrome privilege escalation through XPCNativeWrappers.
CVE-2008-4059
   <q>moz_bug_r_a4</q> discovered a vulnerability which can result in
   Chrome privilege escalation through XPCNativeWrappers.
CVE-2008-4060
   Olli Pettay and <q>moz_bug_r_a4</q> discovered a Chrome privilege
   escalation vulnerability in XSLT handling.
CVE-2008-4061
   Jesse Ruderman discovered a crash in the layout engine, which might
   allow the execution of arbitrary code.
CVE-2008-4062
   Igor Bukanov, Philip Taylor, Georgi Guninski and Antoine Labour
   discovered crashes in the Javascript engine, which might allow the
   execution of arbitrary code.
CVE-2008-4065
   Dave Reed discovered that some Unicode byte order marks are
   stripped from Javascript code before execution, which can result in
   code being executed, which were otherwise part of a quoted string.
CVE-2008-4066
   Gareth Heyes discovered that some Unicode surrogate characters are
   ignored by the HTML parser.
CVE-2008-4067
   Boris Zbarsky discovered that resource: URLs allow directory
   traversal when using URL-encoded slashes.
CVE-2008-4068
   Georgi Guninski discovered that resource: URLs could bypass local
   access restrictions.
CVE-2008-4069
   Billy Hoffman discovered that the XBM decoder could reveal
   uninitialised memory.
For the stable distribution (etch), these problems have been fixed in
version 2.0.0.17-0etch1. Packages for hppa will be provided later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1649');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your iceweasel packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1649] DSA-1649-1 iceweasel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1649-1 iceweasel");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'firefox', release: '4.0', reference: '2.0.0.17-0etch1');
deb_check(prefix: 'firefox-dom-inspector', release: '4.0', reference: '2.0.0.17-0etch1');
deb_check(prefix: 'firefox-gnome-support', release: '4.0', reference: '2.0.0.17-0etch1');
deb_check(prefix: 'iceweasel', release: '4.0', reference: '2.0.0.17-0etch1');
deb_check(prefix: 'iceweasel-dbg', release: '4.0', reference: '2.0.0.17-0etch1');
deb_check(prefix: 'iceweasel-dom-inspector', release: '4.0', reference: '2.0.0.17-0etch1');
deb_check(prefix: 'iceweasel-gnome-support', release: '4.0', reference: '2.0.0.17-0etch1');
deb_check(prefix: 'mozilla-firefox', release: '4.0', reference: '2.0.0.17-0etch1');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '4.0', reference: '2.0.0.17-0etch1');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '4.0', reference: '2.0.0.17-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
