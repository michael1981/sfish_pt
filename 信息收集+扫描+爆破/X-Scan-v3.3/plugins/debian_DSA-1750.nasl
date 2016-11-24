# This script was automatically generated from the dsa-1750
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35988);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1750");
 script_cve_id("CVE-2007-2445", "CVE-2007-5269", "CVE-2008-1382", "CVE-2008-5907", "CVE-2008-6218", "CVE-2009-0040");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1750 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in libpng, a library for
reading and writing PNG files. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2007-2445
   The png_handle_tRNS function allows attackers to cause a denial of service
   (application crash) via a grayscale PNG image with a bad tRNS chunk CRC value.
CVE-2007-5269
   Certain chunk handlers allow attackers to cause a denial of service (crash)
   via crafted pCAL, sCAL, tEXt, iTXt, and ztXT chunking in PNG images, which
   trigger out-of-bounds read operations.
CVE-2008-1382
   libpng allows context-dependent attackers to cause a denial of service
   (crash) and possibly execute arbitrary code via a PNG file with zero
   length "unknown" chunks, which trigger an access of uninitialized
   memory.
CVE-2008-5907
   The png_check_keyword might allow context-dependent attackers to set the
   value of an arbitrary memory location to zero via vectors involving
   creation of crafted PNG files with keywords.
CVE-2008-6218
   A memory leak in the png_handle_tEXt function allows context-dependent
   attackers to cause a denial of service (memory exhaustion) via a crafted
   PNG file.
CVE-2009-0040
   libpng allows context-dependent attackers to cause a denial of service
   (application crash) or possibly execute arbitrary code via a crafted PNG
   file that triggers a free of an uninitialized pointer in (1) the
   png_read_png function, (2) pCAL chunk handling, or (3) setup of 16-bit
   gamma tables.
For the old stable distribution (etch), these problems have been fixed
in version 1.2.15~beta5-1+etch2.
For the stable distribution (lenny), these problems have been fixed in
version 1.2.27-2+lenny2.  (Only CVE-2008-5907, CVE-2008-5907 and
CVE-2009-0040 affect the stable distribution.)
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1750');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libpng packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1750] DSA-1750-1 libpng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1750-1 libpng");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpng12-0', release: '5.0', reference: '1.2.27-2+lenny2');
deb_check(prefix: 'libpng12-dev', release: '5.0', reference: '1.2.27-2+lenny2');
deb_check(prefix: 'libpng3', release: '5.0', reference: '1.2.27-2+lenny2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
