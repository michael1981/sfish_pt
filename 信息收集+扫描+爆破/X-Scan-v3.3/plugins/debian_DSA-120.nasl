# This script was automatically generated from the dsa-120
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14957);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "120");
 script_cve_id("CVE-2002-0082");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-120 security update');
 script_set_attribute(attribute: 'description', value:
'Ed Moyle recently
found a buffer overflow in Apache-SSL and mod_ssl.
With session caching enabled, mod_ssl will serialize SSL session
variables to store them for later use.  These variables were stored in
a buffer of a fixed size without proper boundary checks.
To exploit the overflow, the server must be configured to require client
certificates, and an attacker must obtain a carefully crafted client
certificate that has been signed by a Certificate Authority which is
trusted by the server. If these conditions are met, it would be possible
for an attacker to execute arbitrary code on the server.
This problem has been fixed in version 1.3.9.13-4 of Apache-SSL and
version 2.4.10-1.3.9-1potato1 of libapache-mod-ssl for the stable
Debian distribution as well as in version 1.3.23.1+1.47-1 of
Apache-SSL and version 2.8.7-1 of libapache-mod-ssl for the testing
and unstable distribution of Debian.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-120');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Apache-SSL and mod_ssl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA120] DSA-120-1 mod_ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-120-1 mod_ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache-ssl', release: '2.2', reference: '1.3.9.13-4');
deb_check(prefix: 'libapache-mod-ssl', release: '2.2', reference: '2.4.10-1.3.9-1potato1');
deb_check(prefix: 'libapache-mod-ssl-doc', release: '2.2', reference: '2.4.10-1.3.9-1potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
