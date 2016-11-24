# This script was automatically generated from the dsa-1137
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22679);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1137");
 script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1137 security update');
 script_set_attribute(attribute: 'description', value:
'Tavis Ormandy of the Google Security Team discovered several problems
in the TIFF library.  The Common Vulnerabilities and Exposures project
identifies the following issues:
CVE-2006-3459
    Several stack-buffer overflows have been discovered.
CVE-2006-3460
    A heap overflow vulnerability in the JPEG decoder may overrun a
    buffer with more data than expected.
CVE-2006-3461
    A heap overflow vulnerability in the PixarLog decoder may allow an
    attacker to execute arbitrary code.
CVE-2006-3462
    A heap overflow vulnerability has been discovered in the NeXT RLE
    decoder.
CVE-2006-3463
    An loop was discovered where a 16bit unsigned short was used to
    iterate over a 32bit unsigned value so that the loop would never
    terminate and continue forever.
CVE-2006-3464
    Multiple unchecked arithmetic operations were uncovered, including
    a number of the range checking operations designed to ensure the
    offsets specified in TIFF directories are legitimate.
CVE-2006-3465
    A flaw was also uncovered in libtiffs custom tag support which may
    result in abnormal behaviour, crashes, or potentially arbitrary
    code execution.
For the stable distribution (sarge) these problems have been fixed in
version 3.7.2-7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1137');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libtiff packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1137] DSA-1137-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1137-1 tiff");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtiff-opengl', release: '3.1', reference: '3.7.2-7');
deb_check(prefix: 'libtiff-tools', release: '3.1', reference: '3.7.2-7');
deb_check(prefix: 'libtiff4', release: '3.1', reference: '3.7.2-7');
deb_check(prefix: 'libtiff4-dev', release: '3.1', reference: '3.7.2-7');
deb_check(prefix: 'libtiffxx0', release: '3.1', reference: '3.7.2-7');
deb_check(prefix: 'tiff', release: '3.1', reference: '3.7.2-7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
