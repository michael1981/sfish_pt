# This script was automatically generated from the dsa-1728
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35752);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1728");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1728 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that dkim-milter, an implementation of the DomainKeys
Identified Mail protocol, may crash during DKIM verification if it
encounters a specially-crafted or revoked public key record in DNS.
The old stable distribution (etch) does not contain dkim-milter packages.
For the stable distribution (lenny), this problem has been fixed in
version 2.6.0.dfsg-1+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1728');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your dkim-milter packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1728] DSA-1728-1 dkim-milter");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1728-1 dkim-milter");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'dkim-filter', release: '5.0', reference: '2.6.0.dfsg-1+lenny1');
deb_check(prefix: 'libsmdkim-dev', release: '5.0', reference: '2.6.0.dfsg-1+lenny1');
deb_check(prefix: 'libsmdkim2', release: '5.0', reference: '2.6.0.dfsg-1+lenny1');
deb_check(prefix: 'dkim-milter', release: '5.0', reference: '2.6.0.dfsg-1+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
