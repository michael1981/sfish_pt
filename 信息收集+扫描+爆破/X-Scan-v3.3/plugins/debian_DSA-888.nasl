# This script was automatically generated from the dsa-888
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22754);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "888");
 script_cve_id("CVE-2005-2969");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-888 security update');
 script_set_attribute(attribute: 'description', value:
'Yutaka Oiwa discovered a vulnerability in the Open Secure Socket Layer
(OpenSSL) library that can allow an attacker to perform active
protocol-version rollback attacks that could lead to the use of the
weaker SSL 2.0 protocol even though both ends support SSL 3.0 or TLS
1.0.
The following matrix explains which version in which distribution has
this problem corrected.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-888');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libssl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA888] DSA-888-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-888-1 openssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.8');
deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.8');
deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.8');
deb_check(prefix: 'ssleay', release: '3.0', reference: '0.9.6c-2.woody.8');
deb_check(prefix: 'libssl-dev', release: '3.1', reference: '0.9.7e-3sarge1');
deb_check(prefix: 'libssl0.9.7', release: '3.1', reference: '0.9.7e-3sarge1');
deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7e-3sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
