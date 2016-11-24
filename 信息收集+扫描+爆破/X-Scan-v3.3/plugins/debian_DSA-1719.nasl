# This script was automatically generated from the dsa-1719
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35637);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1719");
 script_cve_id("CVE-2008-4989");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1719 security update');
 script_set_attribute(attribute: 'description', value:
'Martin von Gagern discovered that GNUTLS, an implementation of the
TLS/SSL protocol, handles verification of X.509 certificate chains
incorrectly if a self-signed certificate is configured as a trusted
certificate.  This could cause clients to accept forged server
certificates as genuine.  (CVE-2008-4989)
In addition, this update tightens the checks for X.509v1 certificates
which causes GNUTLS to reject certain certificate chains it accepted
before.  (In certificate chain processing, GNUTLS does not recognize
X.509v1 certificates as valid unless explicitly requested by the
application.)
For the stable distribution (etch), this problem has been fixed in
version 1.4.4-3+etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1719');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnutls13 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1719] DSA-1719-1 gnutls13");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1719-1 gnutls13");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnutls-bin', release: '4.0', reference: '1.4.4-3+etch3');
deb_check(prefix: 'gnutls-doc', release: '4.0', reference: '1.4.4-3+etch3');
deb_check(prefix: 'libgnutls-dev', release: '4.0', reference: '1.4.4-3+etch2');
deb_check(prefix: 'libgnutls13', release: '4.0', reference: '1.4.4-3+etch3');
deb_check(prefix: 'libgnutls13-dbg', release: '4.0', reference: '1.4.4-3+etch3');
deb_check(prefix: 'gnutls13', release: '4.0', reference: '1.4.4-3+etch3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
