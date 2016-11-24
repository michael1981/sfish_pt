# This script was automatically generated from the dsa-765
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19270);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "765");
 script_cve_id("CVE-2005-0469");
 script_xref(name: "CERT", value: "291924");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-765 security update');
 script_set_attribute(attribute: 'description', value:
'Gaël Delalleau discovered a buffer overflow in the handling of the
LINEMODE suboptions in telnet clients.  Heimdal, a free implementation
of Kerberos 5, also contains such a client.  This can lead to the
execution of arbitrary code when connected to a malicious server.
For the old stable distribution (woody) this problem has been fixed in
version 0.4e-7.woody.11.
For the stable distribution (sarge) this problem has been fixed in
version 0.6.3-10.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-765');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your heimdal package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA765] DSA-765-1 heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-765-1 heimdal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'heimdal-clients', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'heimdal-clients-x', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'heimdal-dev', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'heimdal-docs', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'heimdal-kdc', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'heimdal-lib', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'heimdal-servers', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'heimdal-servers-x', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libasn1-5-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libcomerr1-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libgssapi1-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libhdb7-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libkadm5clnt4-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libkadm5srv7-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libkafs0-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libkrb5-17-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libotp0-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libroken9-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libsl0-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'libss0-heimdal', release: '3.0', reference: '0.4e-7.woody.11');
deb_check(prefix: 'heimdal', release: '3.1', reference: '0.6.3-10');
deb_check(prefix: 'heimdal', release: '3.0', reference: '0.4e-7.woody.11');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
