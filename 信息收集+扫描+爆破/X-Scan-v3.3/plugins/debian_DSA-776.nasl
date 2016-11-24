# This script was automatically generated from the dsa-776
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19432);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "776");
 script_cve_id("CVE-2005-2450");
 script_bugtraq_id(14359);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-776 security update');
 script_set_attribute(attribute: 'description', value:
'Several bugs were discovered in Clam AntiVirus, the antivirus scanner
for Unix, designed for integration with mail servers to perform
attachment scanning.  The following problems were identified:
    Neel Mehta and Alex Wheeler discovered that Clam AntiVirus is
    vulnerable to integer overflows when handling the TNEF, CHM and
    FSG file formats.
    Mark Pizzolato fixed a possible infinite loop that could cause a
    denial of service.
The old stable distribution (woody) is not affected as it doesn\'t contain clamav.
For the stable distribution (sarge) these problems have been fixed in
version 0.84-2.sarge.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-776');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your clamav package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA776] DSA-776-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-776-1 clamav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'clamav', release: '3.1', reference: '0.84-2.sarge.2');
deb_check(prefix: 'clamav-base', release: '3.1', reference: '0.84-2.sarge.2');
deb_check(prefix: 'clamav-daemon', release: '3.1', reference: '0.84-2.sarge.2');
deb_check(prefix: 'clamav-docs', release: '3.1', reference: '0.84-2.sarge.2');
deb_check(prefix: 'clamav-freshclam', release: '3.1', reference: '0.84-2.sarge.2');
deb_check(prefix: 'clamav-milter', release: '3.1', reference: '0.84-2.sarge.2');
deb_check(prefix: 'clamav-testfiles', release: '3.1', reference: '0.84-2.sarge.2');
deb_check(prefix: 'libclamav-dev', release: '3.1', reference: '0.84-2.sarge.2');
deb_check(prefix: 'libclamav1', release: '3.1', reference: '0.84-2.sarge.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
