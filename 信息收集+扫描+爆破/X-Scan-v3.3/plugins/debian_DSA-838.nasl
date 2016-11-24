# This script was automatically generated from the dsa-838
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19807);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "838");
 script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-838 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple security vulnerabilities have been identified in the
mozilla-firefox web browser. These vulnerabilities could allow an
attacker to execute code on the victim\'s machine via specially crafted
network resources.
	Heap overrun in XBM image processing
	Denial of service (crash) and possible execution of arbitrary
	code via Unicode sequences with "zero-width non-joiner"
	characters.
	XMLHttpRequest header spoofing
	Object spoofing using XBL <implements>
	JavaScript integer overflow
	Privilege escalation using about: scheme
	Chrome window spoofing allowing windows to be created without
	UI components such as a URL bar or status bar that could be
	used to carry out phishing attacks
For the stable distribution (sarge), these problems have been fixed in
version 1.0.4-2sarge5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-838');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mozilla-firefox package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA838] DSA-838-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-838-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge5');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge5');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
