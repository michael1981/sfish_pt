# This script was automatically generated from the dsa-1333
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25742);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1333");
 script_cve_id("CVE-2007-3564");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1333 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered that the GnuTLS certificate verification methods
implemented in libcurl-gnutls, a solid, usable, and portable multi-protocol
file transfer library, did not check for expired or invalid dates.
For the stable distribution (etch), this problem has been fixed in
version 7.15.5-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1333');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libcurl3-gnutls package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1333] DSA-1333-1 libcurl3-gnutls");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1333-1 libcurl3-gnutls");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'curl', release: '4.0', reference: '7.15.5-1etch1');
deb_check(prefix: 'libcurl3', release: '4.0', reference: '7.15.5-1etch1');
deb_check(prefix: 'libcurl3-dbg', release: '4.0', reference: '7.15.5-1etch1');
deb_check(prefix: 'libcurl3-dev', release: '4.0', reference: '7.15.5-1etch1');
deb_check(prefix: 'libcurl3-gnutls', release: '4.0', reference: '7.15.5-1etch1');
deb_check(prefix: 'libcurl3-gnutls-dev', release: '4.0', reference: '7.15.5-1etch1');
deb_check(prefix: 'libcurl3-openssl-dev', release: '4.0', reference: '7.15.5-1etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
