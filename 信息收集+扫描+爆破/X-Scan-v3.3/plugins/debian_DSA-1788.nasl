# This script was automatically generated from the dsa-1788
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38690);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1788");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1788 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that Quagga, an IP routing daemon, could no longer
process the Internet routing table due to broken handling of multiple
4-byte AS numbers in an AS path.  If such a prefix is received, the
BGP daemon crashes with an assert failure, leading to a denial of
service.
The old stable distribution (etch) is not affected by this issue.
For the stable distribution (lenny), this problem has been fixed in
version 0.99.10-1lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1788');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your quagga package.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1788] DSA-1788-1 quagga");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1788-1 quagga");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'quagga', release: '5.0', reference: '0.99.10-1lenny2');
deb_check(prefix: 'quagga-doc', release: '5.0', reference: '0.99.10-1lenny2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
