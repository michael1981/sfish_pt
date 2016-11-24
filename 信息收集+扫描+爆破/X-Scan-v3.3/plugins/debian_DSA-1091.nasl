# This script was automatically generated from the dsa-1091
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22633);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1091");
 script_cve_id("CVE-2006-2193", "CVE-2006-2656");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1091 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in the TIFF library.  The Common
Vulnerabilities and Exposures project identifies the following issues:
CVE-2006-2193
    SuSE discovered a buffer overflow in the conversion of TIFF files
    into PDF documents which could be exploited when tiff2pdf is used
    e.g. in a printer filter.
CVE-2006-2656
    The tiffsplit command from the TIFF library contains a buffer
    overflow in the commandline handling which could be exploited when
    the program is executed automatically on unknown filenames.
For the old stable distribution (woody) this problem has been fixed in
version 3.5.5-7woody2.
For the stable distribution (sarge) this problem has been fixed in
version 3.7.2-5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1091');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tiff packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1091] DSA-1091-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1091-1 tiff");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtiff-tools', release: '3.0', reference: '3.5.5-7woody2');
deb_check(prefix: 'libtiff3g', release: '3.0', reference: '3.5.5-7woody2');
deb_check(prefix: 'libtiff3g-dev', release: '3.0', reference: '3.5.5-7woody2');
deb_check(prefix: 'libtiff-opengl', release: '3.1', reference: '3.7.2-5');
deb_check(prefix: 'libtiff-tools', release: '3.1', reference: '3.7.2-5');
deb_check(prefix: 'libtiff4', release: '3.1', reference: '3.7.2-5');
deb_check(prefix: 'libtiff4-dev', release: '3.1', reference: '3.7.2-5');
deb_check(prefix: 'libtiffxx0', release: '3.1', reference: '3.7.2-5');
deb_check(prefix: 'tiff', release: '3.1', reference: '3.7.2-5');
deb_check(prefix: 'tiff', release: '3.0', reference: '3.5.5-7woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
