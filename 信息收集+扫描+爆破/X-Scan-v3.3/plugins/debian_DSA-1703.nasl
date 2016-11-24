# This script was automatically generated from the dsa-1703
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35366);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1703");
 script_cve_id("CVE-2009-0025");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1703 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that BIND, an implementation of the DNS protocol
suite, does not properly check the result of an OpenSSL function which
is used to verify DSA cryptographic signatures.  As a result,
incorrect DNS resource records in zones protected by DNSSEC could be
accepted as genuine.
For the stable distribution (etch), this problem has been fixed in
version 9.3.4-2etch4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1703');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your BIND packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1703] DSA-1703-1 bind9");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1703-1 bind9");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bind9', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'bind9-doc', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'bind9-host', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'dnsutils', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'libbind-dev', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'libbind9-0', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'libdns22', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'libisc11', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'libisccc0', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'libisccfg1', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'liblwres9', release: '4.0', reference: '9.3.4-2etch4');
deb_check(prefix: 'lwresd', release: '4.0', reference: '9.3.4-2etch4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
