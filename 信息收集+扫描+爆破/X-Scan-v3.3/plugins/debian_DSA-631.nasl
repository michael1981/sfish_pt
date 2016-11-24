# This script was automatically generated from the dsa-631
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16128);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "631");
 script_cve_id("CVE-2004-1165");
 script_bugtraq_id(11827);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-631 security update');
 script_set_attribute(attribute: 'description', value:
'Thiago Macieira discovered a vulnerability in the kioslave library,
which is part of kdelibs, which allows a remote attacker to execute
arbitrary FTP commands via an ftp:// URL that contains a URL-encoded
newline before the FTP command.
For the stable distribution (woody) this problem has been fixed in
version 2.2.2-13.woody.13.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-631');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your kdelibs3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA631] DSA-631-1 kdelibs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-631-1 kdelibs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kdelibs-dev', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'kdelibs3', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'kdelibs3-bin', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'kdelibs3-cups', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'kdelibs3-doc', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'libarts', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'libarts-alsa', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'libarts-dev', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'libkmid', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'libkmid-alsa', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'libkmid-dev', release: '3.0', reference: '2.2.2-13.woody.13');
deb_check(prefix: 'kdelibs', release: '3.0', reference: '2.2.2-13.woody.13');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
