# This script was automatically generated from the dsa-1487
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30226);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1487");
 script_cve_id("CVE-2007-2645", "CVE-2007-6351", "CVE-2007-6352");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1487 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the EXIF parsing code
of the libexif library, which can lead to denial of service or the 
execution of arbitrary code if a user is tricked into opening a
malformed image.  The Common Vulnerabilities and Exposures project identifies
the following problems:
CVE-2007-2645
    Victor Stinner discovered an integer overflow, which may result in
    denial of service or potentially the execution of arbitrary code.
CVE-2007-6351
    Meder Kydyraliev discovered an infinite loop, which may result in
    denial of service.
CVE-2007-6352
    Victor Stinner discovered an integer overflow, which may result
    in denial of service or potentially the execution of arbitrary
    code.
This update also fixes two potential NULL pointer deferences.
For the old stable distribution (sarge), these problems have been
fixed in 0.6.9-6sarge2.
For the stable distribution (etch), these problems have been fixed in
version 0.6.13-5etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1487');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libexif packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1487] DSA-1487-1 libexif");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1487-1 libexif");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libexif-dev', release: '3.1', reference: '0.6.9-6sarge2');
deb_check(prefix: 'libexif10', release: '3.1', reference: '0.6.9-6sarge2');
deb_check(prefix: 'libexif-dev', release: '4.0', reference: '0.6.13-5etch2');
deb_check(prefix: 'libexif12', release: '4.0', reference: '0.6.13-5etch2');
deb_check(prefix: 'libexif', release: '4.0', reference: '0.6.13-5etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
