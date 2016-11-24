# This script was automatically generated from the dsa-1804
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38861);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1804");
 script_cve_id("CVE-2009-1574", "CVE-2009-1632");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1804 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in racoon, the Internet Key
Exchange daemon of ipsec-tools.  The The Common Vulnerabilities and Exposures
project identified the following problems:
CVE-2009-1574
Neil Kettle discovered a NULL pointer dereference on crafted fragmented packets
that contain no payload.  This results in the daemon crashing which can be used
for denial of service attacks.
CVE-2009-1632
Various memory leaks in the X.509 certificate authentication handling and the
NAT-Traversal keepalive implementation can result in memory exhaustion and
thus denial of service.
For the oldstable distribution (etch), this problem has been fixed in
version 0.6.6-3.1etch3.
For the stable distribution (lenny), this problem has been fixed in
version 0.7.1-1.3+lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1804');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ipsec-tools packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1804] DSA-1804-1 ipsec-tools");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1804-1 ipsec-tools");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ipsec-tools', release: '4.0', reference: '0.6.6-3.1etch3');
deb_check(prefix: 'racoon', release: '4.0', reference: '0.6.6-3.1etch3');
deb_check(prefix: 'ipsec-tools', release: '5.0', reference: '0.7.1-1.3+lenny2');
deb_check(prefix: 'racoon', release: '5.0', reference: '0.7.1-1.3+lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
