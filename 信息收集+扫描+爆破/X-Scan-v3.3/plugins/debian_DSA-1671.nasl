# This script was automatically generated from the dsa-1671
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34950);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1671");
 script_cve_id("CVE-2008-0017", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5017", "CVE-2008-5018");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1671 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Iceweasel
webbrowser, an unbranded version of the Firefox browser. The Common 
Vulnerabilities and Exposures project identifies the following problems:
CVE-2008-0017
   Justin Schuh discovered that a buffer overflow in the http-index-format
   parser could lead to arbitrary code execution.
CVE-2008-4582
   Liu Die Yu discovered an information leak through local shortcut
   files.
CVE-2008-5012
   Georgi Guninski, Michal Zalewski and Chris Evan discovered that
   the canvas element could be used to bypass same-origin
   restrictions.
CVE-2008-5013
   It was discovered that insufficient checks in the Flash plugin glue
   code could lead to arbitrary code execution.
CVE-2008-5014
   Jesse Ruderman discovered that a programming error in the
   window.__proto__.__proto__ object could lead to arbitrary code
   execution.
CVE-2008-5017
   It was discovered that crashes in the layout engine could lead to
   arbitrary code execution.
CVE-2008-5018
   It was discovered that crashes in the Javascript engine could lead to
   arbitrary code execution.
CVE-2008-5021
   It was discovered that a crash in the nsFrameManager might lead to
   the execution of arbitrary code.
CVE-2008-5022
   <q>moz_bug_r_a4</q> discovered that the same-origin check in
   nsXMLHttpRequest::NotifyEventListeners() could be bypassed.
CVE-2008-5023
   Collin Jackson discovered that the -moz-binding property bypasses
   security checks on codebase principals.
CVE-2008-5024
   Chris Evans discovered that quote characters were improperly
   escaped in the default namespace of E4X documents.
For the stable distribution (etch), these problems have been fixed in
version 2.0.0.18-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1671');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your iceweasel package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1671] DSA-1671-1 iceweasel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1671-1 iceweasel");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'firefox', release: '4.0', reference: '2.0.0.18-0etch1');
deb_check(prefix: 'firefox-dom-inspector', release: '4.0', reference: '2.0.0.18-0etch1');
deb_check(prefix: 'firefox-gnome-support', release: '4.0', reference: '2.0.0.18-0etch1');
deb_check(prefix: 'iceweasel', release: '4.0', reference: '2.0.0.18-0etch1');
deb_check(prefix: 'iceweasel-dbg', release: '4.0', reference: '2.0.0.18-0etch1');
deb_check(prefix: 'iceweasel-dom-inspector', release: '4.0', reference: '2.0.0.18-0etch1');
deb_check(prefix: 'iceweasel-gnome-support', release: '4.0', reference: '2.0.0.18-0etch1');
deb_check(prefix: 'mozilla-firefox', release: '4.0', reference: '2.0.0.18-0etch1');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '4.0', reference: '2.0.0.18-0etch1');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '4.0', reference: '2.0.0.18-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
