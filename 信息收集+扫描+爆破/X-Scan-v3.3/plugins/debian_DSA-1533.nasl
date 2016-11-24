# This script was automatically generated from the dsa-1533
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31710);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1533");
 script_cve_id("CVE-2007-6354", "CVE-2007-6355", "CVE-2007-6356");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1533 security update');
 script_set_attribute(attribute: 'description', value:
'Christian Schmid and Meder Kydyraliev (Google Security) discovered a
number of vulnerabilities in exiftags, a utility for extracting EXIF
metadata from JPEG images. The Common Vulnerabilities and Exposures
project identified the following three problems:
CVE-2007-6354
    Inadequate EXIF property validation could lead to invalid memory
    accesses if executed on a maliciously crafted image, potentially
    including heap corruption and the execution of arbitrary code.
CVE-2007-6355
    Flawed data validation could lead to integer overflows, causing
    other invalid memory accesses, also with the potential for memory
    corruption or arbitrary code execution.
CVE-2007-6356
    Cyclical EXIF image file directory (IFD) references could cause
    a denial of service (infinite loop).
For the oldstable distribution (sarge), these problems have been fixed
in version 0.98-1.1+0sarge1.
For the stable distribution (etch), these problems have been fixed in
version 0.98-1.1+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1533');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2008/dsa-1533
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1533] DSA-1533-2 exiftags");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1533-2 exiftags");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'exiftags', release: '3.1', reference: '0.98-1.1+0sarge1');
deb_check(prefix: 'exiftags', release: '4.0', reference: '0.98-1.1+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
