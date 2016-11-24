# This script was automatically generated from the dsa-1322
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25616);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1322");
 script_cve_id("CVE-2007-3390", "CVE-2007-3392", "CVE-2007-3393");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1322 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Wireshark
network traffic analyzer, which may lead to denial of service. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-3390
    Off-by-one overflows were discovered in the iSeries dissector.
CVE-2007-3392
    The MMS and SSL dissectors could be forced into an infinite loop.
CVE-2007-3393
    An off-by-one overflow was discovered in the DHCP/BOOTP dissector.
The oldstable distribution (sarge) is not affected by these problems.
(In Sarge Wireshark used to be called Ethereal).
For the stable distribution (etch) these problems have been fixed
in version 0.99.4-5.etch.0. Packages for the big endian MIPS architecture
are not yet available. They will be provided later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1322');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Wireshark packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1322] DSA-1322-1 wireshark");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1322-1 wireshark");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '4.0', reference: '0.99.4-5.etch.0');
deb_check(prefix: 'ethereal-common', release: '4.0', reference: '0.99.4-5.etch.0');
deb_check(prefix: 'ethereal-dev', release: '4.0', reference: '0.99.4-5.etch.0');
deb_check(prefix: 'tethereal', release: '4.0', reference: '0.99.4-5.etch.0');
deb_check(prefix: 'tshark', release: '4.0', reference: '0.99.4-5.etch.0');
deb_check(prefix: 'wireshark', release: '4.0', reference: '0.99.4-5.etch.0');
deb_check(prefix: 'wireshark-common', release: '4.0', reference: '0.99.4-5.etch.0');
deb_check(prefix: 'wireshark-dev', release: '4.0', reference: '0.99.4-5.etch.0');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
