# This script was automatically generated from the dsa-1737
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35907);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1737");
 script_cve_id("CVE-2009-0366", "CVE-2009-0367");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1737 security update');
 script_set_attribute(attribute: 'description', value:
'Several security issues have been discovered in wesnoth, a fantasy
turn-based strategy game. The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2009-0366
Daniel Franke discovered that the wesnoth server is prone to a denial of
service attack when receiving special crafted compressed data.
CVE-2009-0367
Daniel Franke discovered that the sandbox implementation for the python
AIs can be used to execute arbitrary python code on wesnoth clients. In
order to prevent this issue, the python support has been disabled. A
compatibility patch was included, so that the affected campagne is still
working properly.
For the stable distribution (lenny), these problems have been fixed in
version 1.4.4-2+lenny1.
For the oldstable distribution (etch), these problems have been fixed
in version 1.2-5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1737');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wesnoth packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1737] DSA-1737-1 wesnoth");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1737-1 wesnoth");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wesnoth', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-all', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-aoi', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-data', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-dbg', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-did', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-editor', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-ei', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-httt', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-l', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-music', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-nr', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-server', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-sof', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-sotbe', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-thot', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-tools', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-trow', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-tsg', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-ttb', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth-utbs', release: '4.0', reference: '1.4.4-2+lenny1');
deb_check(prefix: 'wesnoth', release: '4.0', reference: '1.2-5');
deb_check(prefix: 'wesnoth', release: '5.0', reference: '1.4.4-2+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
