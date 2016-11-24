# This script was automatically generated from the dsa-394
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15231);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "394");
 script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
 script_bugtraq_id(8732);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-394 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Henson of the OpenSSL core team identified and prepared fixes
for a number of vulnerabilities in the OpenSSL ASN1 code that were
discovered after running a test suite by British National
Infrastructure Security Coordination Centre (NISCC).
A bug in OpenSSLs SSL/TLS protocol was also identified which causes
OpenSSL to parse a client certificate from an SSL/TLS client when it
should reject it as a protocol error.
The Common Vulnerabilities and Exposures project identifies the
following problems:
Integer overflow in OpenSSL that allows remote attackers to cause a
   denial of service (crash) via an SSL client certificate with
   certain ASN.1 tag values.
OpenSSL does not properly track the number of characters in certain
   ASN.1 inputs, which allows remote attackers to cause a denial of
   service (crash) via an SSL client certificate that causes OpenSSL
   to read past the end of a buffer when the long form is used.
Double-free vulnerability allows remote attackers to cause a denial
   of service (crash) and possibly execute arbitrary code via an SSL
   client certificate with a certain invalid ASN.1 encoding.  This bug
   was only present in OpenSSL 0.9.7 and is listed here only for
   reference.
For the stable distribution (woody) this problem has been
fixed in openssl095 version 0.9.5a-6.woody.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-394');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libssl095a packages and restart
services using this library.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA394] DSA-394-1 openssl095");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-394-1 openssl095");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl095a', release: '3.0', reference: '0.9.5a-6.woody.3');
deb_check(prefix: 'openssl095', release: '3.0', reference: '0.9.5a-6.woody.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
