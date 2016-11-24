# This script was automatically generated from the dsa-1173
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22715);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1173");
 script_cve_id("CVE-2006-4339");
 script_bugtraq_id(19849);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1173 security update');
 script_set_attribute(attribute: 'description', value:
'Daniel Bleichenbacher discovered a flaw in the OpenSSL cryptographic package
that could allow an attacker to generate a forged signature that OpenSSL
will accept as valid.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.7e-3sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1173');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openssl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1173] DSA-1173-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1173-1 openssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libssl-dev', release: '3.1', reference: '0.9.7e-3sarge2');
deb_check(prefix: 'libssl0.9.7', release: '3.1', reference: '0.9.7e-3sarge2');
deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7e-3sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
