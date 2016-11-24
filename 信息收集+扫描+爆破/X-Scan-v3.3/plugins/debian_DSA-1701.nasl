# This script was automatically generated from the dsa-1701
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35364);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1701");
 script_cve_id("CVE-2008-5077");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1701 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that OpenSSL does not properly verify DSA signatures
on X.509 certificates due to an API misuse, potentially leading to the
acceptance of incorrect X.509 certificates as genuine (CVE-2008-5077).
For the stable distribution (etch), this problem has been fixed in
version 0.9.8c-4etch4 of the openssl package, and version
0.9.7k-3.1etch2 of the openssl097 package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1701');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your OpenSSL packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1701] DSA-1701-1 openssl, openssl097");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1701-1 openssl, openssl097");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl-dev', release: '4.0', reference: '0.9.8c-4etch4');
deb_check(prefix: 'libssl0.9.7', release: '4.0', reference: '0.9.7k-3.1etch2');
deb_check(prefix: 'libssl0.9.7-dbg', release: '4.0', reference: '0.9.7k-3.1etch2');
deb_check(prefix: 'libssl0.9.8', release: '4.0', reference: '0.9.8c-4etch4');
deb_check(prefix: 'libssl0.9.8-dbg', release: '4.0', reference: '0.9.8c-4etch4');
deb_check(prefix: 'openssl', release: '4.0', reference: '0.9.8c-4etch4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
