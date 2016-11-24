# This script was automatically generated from the dsa-1379
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(26209);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1379");
 script_cve_id("CVE-2007-5135");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1379 security update');
 script_set_attribute(attribute: 'description', value:
'An off-by-one error has been identified in the SSL_get_shared_ciphers()
routine in the libssl library from OpenSSL, an implementation of Secure
Socket Layer cryptographic libraries and utilities.  This error could
allow an attacker to crash an application making use of OpenSSL\'s libssl
library, or potentially execute arbitrary code in the security context
of the user running such an application.

For the old stable distribution (sarge), this problem has been fixed in version
0.9.7e-3sarge5.


For the stable distribution (etch), this problem has been fixed in
version 0.9.8c-4etch1.


For the unstable and testing distributions (sid and lenny, respectively),
this problem has been fixed in version 0.9.8e-9.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1379');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openssl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1379] DSA-1379-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1379-1 openssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl-dev', release: '3.1', reference: '0.9.7e-3sarge5');
deb_check(prefix: 'libssl0.9.7', release: '3.1', reference: '0.9.7e-3sarge5');
deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7e-3sarge5');
deb_check(prefix: 'libssl-dev', release: '4.0', reference: '0.9.8c-4etch1');
deb_check(prefix: 'libssl0.9.8', release: '4.0', reference: '0.9.8c-4etch1');
deb_check(prefix: 'libssl0.9.8-dbg', release: '4.0', reference: '0.9.8c-4etch1');
deb_check(prefix: 'openssl', release: '4.0', reference: '0.9.8c-4etch1');
deb_check(prefix: 'openssl', release: '5.0', reference: '0.9.8e-9');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
