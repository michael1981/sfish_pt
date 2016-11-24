# This script was automatically generated from the dsa-288
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15125);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "288");
 script_cve_id("CVE-2003-0131", "CVE-2003-0147");
 script_bugtraq_id(7101, 7148);
 script_xref(name: "CERT", value: "888801");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-288 security update');
 script_set_attribute(attribute: 'description', value:
'Researchers discovered two flaws in OpenSSL, a Secure Socket Layer
(SSL) library and related cryptographic tools.  Applications that are
linked against this library are generally vulnerable to attacks that
could leak the server\'s private key or make the encrypted session
decryptable otherwise.  The Common Vulnerabilities and Exposures (CVE)
project identified the following vulnerabilities:
For the stable distribution (woody) these problems have been fixed in
version 0.9.6c-2.woody.3.
For the old stable distribution (potato) these problems have been
fixed in version 0.9.6c-0.potato.6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-288');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openssl packages immediately and
restart the applications that use OpenSSL.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA288] DSA-288-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-288-1 openssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl-dev', release: '2.2', reference: '0.9.6c-0.potato.6');
deb_check(prefix: 'libssl0.9.6', release: '2.2', reference: '0.9.6c-0.potato.6');
deb_check(prefix: 'openssl', release: '2.2', reference: '0.9.6c-0.potato.6');
deb_check(prefix: 'ssleay', release: '2.2', reference: '0.9.6c-0.potato.6');
deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.3');
deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.3');
deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.3');
deb_check(prefix: 'ssleay', release: '3.0', reference: '0.9.6c-2.woody.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
