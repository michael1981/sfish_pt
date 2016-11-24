# This script was automatically generated from the dsa-1168
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22710);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1168");
 script_cve_id("CVE-2006-2440", "CVE-2006-3743", "CVE-2006-3744");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1168 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Imagemagick, a
collection of image manipulation tools, which may lead to the execution
of arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2006-2440
    Eero Häkkinen discovered that the display tool allocates insufficient
    memory for globbing patterns, which might lead to a buffer overflow.
CVE-2006-3743
    Tavis Ormandy from the Google Security Team discovered that the Sun
    bitmap decoder performs insufficient input sanitising, which might
    lead to buffer overflows and the execution of arbitrary code.
CVE-2006-3744
    Tavis Ormandy from the Google Security Team discovered that the XCF
    image decoder performs insufficient input sanitising, which might
    lead to buffer overflows and the execution of arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 6:6.0.6.2-2.7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1168');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your imagemagick packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1168] DSA-1168-1 imagemagick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1168-1 imagemagick");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'imagemagick', release: '3.1', reference: '6.0.6.2-2.7');
deb_check(prefix: 'libmagick6', release: '3.1', reference: '6.0.6.2-2.7');
deb_check(prefix: 'libmagick6-dev', release: '3.1', reference: '6.0.6.2-2.7');
deb_check(prefix: 'perlmagick', release: '3.1', reference: '6.0.6.2-2.7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
