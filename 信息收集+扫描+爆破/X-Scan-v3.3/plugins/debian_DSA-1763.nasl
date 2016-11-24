# This script was automatically generated from the dsa-1763
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36090);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1763");
 script_cve_id("CVE-2009-0590");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1763 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that insufficient length validations in the ASN.1
handling of the OpenSSL crypto library may lead to denial of service
when processing a manipulated certificate.
For the old stable distribution (etch), this problem has been fixed in
version 0.9.8c-4etch5 of the openssl package and in version
0.9.7k-3.1etch3 of the openssl097 package.
For the stable distribution (lenny), this problem has been fixed in
version 0.9.8g-15+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1763');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openssl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1763] DSA-1763-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1763-1 openssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl-dev', release: '4.0', reference: '0.9.8c-4etch5');
deb_check(prefix: 'libssl0.9.7', release: '4.0', reference: '0.9.7k-3.1etch3');
deb_check(prefix: 'libssl0.9.7-dbg', release: '4.0', reference: '0.9.7k-3.1etch3');
deb_check(prefix: 'libssl0.9.8', release: '4.0', reference: '0.9.8c-4etch5');
deb_check(prefix: 'libssl0.9.8-dbg', release: '4.0', reference: '0.9.8c-4etch5');
deb_check(prefix: 'openssl', release: '4.0', reference: '0.9.8c-4etch5');
deb_check(prefix: 'libssl-dev', release: '5.0', reference: '0.9.8g-15+lenny1');
deb_check(prefix: 'libssl0.9.8', release: '5.0', reference: '0.9.8g-15+lenny1');
deb_check(prefix: 'libssl0.9.8-dbg', release: '5.0', reference: '0.9.8g-15+lenny1');
deb_check(prefix: 'openssl', release: '5.0', reference: '0.9.8g-15+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
