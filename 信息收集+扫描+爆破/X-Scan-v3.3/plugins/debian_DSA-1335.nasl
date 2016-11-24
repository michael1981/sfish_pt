# This script was automatically generated from the dsa-1335
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25744);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1335");
 script_cve_id("CVE-2006-4519", "CVE-2007-2949");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1335 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Gimp, the GNU Image
Manipulation Program, which might lead to the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2006-4519
    Sean Larsson discovered several integer overflows in the processing
    code for DICOM, PNM, PSD, RAS, XBM and XWD images, which might lead
    to the execution of arbitrary code if a user is tricked into opening
    such a malformed media file.
CVE-2007-2949
    Stefan Cornelius discovered an integer overflow in the processing
    code for PSD images, which might lead to the execution of arbitrary
    code if a user is tricked into opening such a malformed media file.
For the oldstable distribution (sarge) these problems have been fixed in
version 2.2.6-1sarge4. Packages for mips and mipsel are not yet
available.
For the stable distribution (etch) these problems have been fixed
in version 2.2.13-1etch4. Packages for mips are not yet available.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1335');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gimp packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1335] DSA-1335-1 gimp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1335-1 gimp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gimp', release: '3.1', reference: '2.2.6-1sarge4');
deb_check(prefix: 'gimp-data', release: '3.1', reference: '2.2.6-1sarge4');
deb_check(prefix: 'gimp-helpbrowser', release: '3.1', reference: '2.2.6-1sarge4');
deb_check(prefix: 'gimp-python', release: '3.1', reference: '2.2.6-1sarge4');
deb_check(prefix: 'gimp-svg', release: '3.1', reference: '2.2.6-1sarge4');
deb_check(prefix: 'gimp1.2', release: '3.1', reference: '2.2.6-1sarge4');
deb_check(prefix: 'libgimp2.0', release: '3.1', reference: '2.2.6-1sarge4');
deb_check(prefix: 'libgimp2.0-dev', release: '3.1', reference: '2.2.6-1sarge4');
deb_check(prefix: 'libgimp2.0-doc', release: '3.1', reference: '2.2.6-1sarge4');
deb_check(prefix: 'gimp', release: '4.0', reference: '2.2.13-1etch4');
deb_check(prefix: 'gimp-data', release: '4.0', reference: '2.2.13-1etch4');
deb_check(prefix: 'gimp-dbg', release: '4.0', reference: '2.2.13-1etch4');
deb_check(prefix: 'gimp-helpbrowser', release: '4.0', reference: '2.2.13-1etch4');
deb_check(prefix: 'gimp-python', release: '4.0', reference: '2.2.13-1etch4');
deb_check(prefix: 'gimp-svg', release: '4.0', reference: '2.2.13-1etch4');
deb_check(prefix: 'libgimp2.0', release: '4.0', reference: '2.2.13-1etch4');
deb_check(prefix: 'libgimp2.0-dev', release: '4.0', reference: '2.2.13-1etch4');
deb_check(prefix: 'libgimp2.0-doc', release: '4.0', reference: '2.2.13-1etch4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
