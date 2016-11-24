# This script was automatically generated from the dsa-393
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15230);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "393");
 script_cve_id("CVE-2003-0543", "CVE-2003-0544");
 script_bugtraq_id(8732);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-393 security update');
 script_set_attribute(attribute: 'description', value:
'Dr. Stephen Henson ("steve@openssl.org"), using a test suite
provided by NISCC ("http://www.niscc.gov.uk/"), discovered a number of
errors in the OpenSSL
ASN1 code.  Combined with an error that causes the OpenSSL code to parse
client certificates even when it should not, these errors can cause a
denial of service (DoS) condition on a system using the OpenSSL code,
depending on how that code is used. For example, even though apache-ssl
and ssh link to OpenSSL libraries, they should not be affected by this
vulnerability. However, other SSL-enabled applications may be
vulnerable and an OpenSSL upgrade is recommended.
For the current stable distribution (woody) these problems have been
fixed in version 0.9.6c-2.woody.4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-393');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-393
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA393] DSA-393-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-393-1 openssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.4');
deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.4');
deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.4');
deb_check(prefix: 'ssleay', release: '3.0', reference: '0.9.6c-2.woody.4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
