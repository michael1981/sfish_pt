# This script was automatically generated from the dsa-465
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15302);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "465");
 script_cve_id("CVE-2004-0079", "CVE-2004-0081");
 script_bugtraq_id(9899);
 script_xref(name: "CERT", value: "288574");
 script_xref(name: "CERT", value: "465542");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-465 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities were discovered in openssl, an implementation of
the SSL protocol, using the Codenomicon TLS Test Tool.  More
information can be found in the following <a
href="http://www.uniras.gov.uk/vuls/2004/224012/index.htm">NISCC
Vulnerability Advisory</a> and this <a
href="http://www.openssl.org/news/secadv_20040317.txt">OpenSSL
advisory</a>.  The Common Vulnerabilities and Exposures project
identified the following vulnerabilities:
   Null-pointer assignment in the
   do_change_cipher_spec() function.  A remote attacker could perform
   a carefully crafted SSL/TLS handshake against a server that used
   the OpenSSL library in such a way as to cause OpenSSL to crash.
   Depending on the application this could lead to a denial of
   service.
   A bug in older versions of OpenSSL 0.9.6 that
   can lead to a Denial of Service attack (infinite loop).
For the stable distribution (woody) these problems have been fixed in
openssl version 0.9.6c-2.woody.6, openssl094 version 0.9.4-6.woody.4
and openssl095 version 0.9.5a-6.woody.5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-465');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-465
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA465] DSA-465-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-465-1 openssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.6');
deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.6');
deb_check(prefix: 'libssl09', release: '3.0', reference: '0.9.4-6.woody.3');
deb_check(prefix: 'libssl095a', release: '3.0', reference: '0.9.5a-6.woody.5');
deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.6');
deb_check(prefix: 'ssleay', release: '3.0', reference: '0.9.6c-2.woody.6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
