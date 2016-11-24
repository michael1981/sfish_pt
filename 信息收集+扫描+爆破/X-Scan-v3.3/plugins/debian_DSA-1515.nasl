# This script was automatically generated from the dsa-1515
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31426);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1515");
 script_cve_id("CVE-2007-3377", "CVE-2007-3409", "CVE-2007-6341");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1515 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in libnet-dns-perl.
The Common Vulnerabilities and Exposures project identifies the
following problems:
It was discovered that libnet-dns-perl generates very weak transaction
IDs when sending queries (CVE-2007-3377).  This update switches
transaction ID generation to the Perl random generator, making
prediction attacks more difficult.
Compression loops in domain names resulted in an infinite loop in the
domain name expander written in Perl (CVE-2007-3409).  The Debian
package uses an expander written in C by default, but this vulnerability
has been addressed nevertheless.
Decoding malformed A records could lead to a crash (via an uncaught
Perl exception) of certain applications using libnet-dns-perl
(CVE-2007-6341).
For the old stable distribution (sarge), these problems have been fixed in
version 0.48-1sarge1.
For the stable distribution (etch), these problems have been fixed in
version 0.59-1etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1515');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libnet-dns-perl package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1515] DSA-1515-1 libnet-dns-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1515-1 libnet-dns-perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnet-dns-perl', release: '3.1', reference: '0.48-1sarge1');
deb_check(prefix: 'libnet-dns-perl', release: '4.0', reference: '0.59-1etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
