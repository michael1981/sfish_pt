# This script was automatically generated from the dsa-1421
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29228);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1421");
 script_cve_id("CVE-2007-5742");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1421 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been discovered in Battle for Wesnoth that allows
remote attackers to read arbitrary files the user running the client
has access to on the machine running the game client.
For the old stable distribution (sarge) this problem has been fixed in
version 0.9.0-7.
For the stable distribution (etch) this problem has been fixed in
version 1.2-3.
For the stable backports distribution (etch-backports) this problem
has been fixed in version 1.2.8-1~bpo40+1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1421');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wesnoth package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1421] DSA-1421-1 wesnoth");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1421-1 wesnoth");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wesnoth', release: '3.1', reference: '0.9.0-7');
deb_check(prefix: 'wesnoth-data', release: '3.1', reference: '0.9.0-7');
deb_check(prefix: 'wesnoth-editor', release: '3.1', reference: '0.9.0-7');
deb_check(prefix: 'wesnoth-ei', release: '3.1', reference: '0.9.0-7');
deb_check(prefix: 'wesnoth-httt', release: '3.1', reference: '0.9.0-7');
deb_check(prefix: 'wesnoth-music', release: '3.1', reference: '0.9.0-7');
deb_check(prefix: 'wesnoth-server', release: '3.1', reference: '0.9.0-7');
deb_check(prefix: 'wesnoth-sotbe', release: '3.1', reference: '0.9.0-7');
deb_check(prefix: 'wesnoth-tdh', release: '3.1', reference: '0.9.0-7');
deb_check(prefix: 'wesnoth-trow', release: '3.1', reference: '0.9.0-7');
deb_check(prefix: 'wesnoth', release: '4.0', reference: '1.2-3');
deb_check(prefix: 'wesnoth-data', release: '4.0', reference: '1.2-3');
deb_check(prefix: 'wesnoth-editor', release: '4.0', reference: '1.2-3');
deb_check(prefix: 'wesnoth-ei', release: '4.0', reference: '1.2-3');
deb_check(prefix: 'wesnoth-httt', release: '4.0', reference: '1.2-3');
deb_check(prefix: 'wesnoth-music', release: '4.0', reference: '1.2-3');
deb_check(prefix: 'wesnoth-server', release: '4.0', reference: '1.2-3');
deb_check(prefix: 'wesnoth-trow', release: '4.0', reference: '1.2-3');
deb_check(prefix: 'wesnoth-tsg', release: '4.0', reference: '1.2-3');
deb_check(prefix: 'wesnoth-ttb', release: '4.0', reference: '1.2-3');
deb_check(prefix: 'wesnoth-utbs', release: '4.0', reference: '1.2-3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
