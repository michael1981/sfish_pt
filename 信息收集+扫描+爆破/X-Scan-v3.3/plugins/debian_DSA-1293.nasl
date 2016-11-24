# This script was automatically generated from the dsa-1293
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25258);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1293");
 script_cve_id("CVE-2007-1995");
 script_bugtraq_id(23417);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1293 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Jakma discovered that specially crafted UPDATE messages can
trigger an out of boundary read that can result in a system crash of
quagga, the BGP/OSPF/RIP routing daemon.
For the old stable distribution (sarge) this problem has been fixed in
version 0.98.3-7.4.
For the stable distribution (etch) this problem has been fixed in
version 0.99.5-5etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1293');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your quagga package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1293] DSA-1293-1 quagga");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1293-1 quagga");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'quagga', release: '3.1', reference: '0.98.3-7.4');
deb_check(prefix: 'quagga-doc', release: '3.1', reference: '0.98.3-7.4');
deb_check(prefix: 'quagga', release: '4.0', reference: '0.99.5-5etch2');
deb_check(prefix: 'quagga-doc', release: '4.0', reference: '0.99.5-5etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
