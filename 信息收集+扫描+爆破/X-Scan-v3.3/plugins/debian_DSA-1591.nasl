# This script was automatically generated from the dsa-1591
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33077);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1591");
 script_cve_id("CVE-2008-1419", "CVE-2008-1420", "CVE-2008-1423");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1591 security update');
 script_set_attribute(attribute: 'description', value:
'Several local (remote) vulnerabilities have been discovered in libvorbis,
a library for the Vorbis general-purpose compressed audio codec. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2008-1419
    libvorbis does not properly handle a zero value which allows remote
    attackers to cause a denial of service (crash or infinite loop) or
    trigger an integer overflow.
CVE-2008-1420
    Integer overflow in libvorbis allows remote attackers to execute
    arbitrary code via a crafted OGG file, which triggers a heap overflow.
CVE-2008-1423
    Integer overflow in libvorbis allows remote attackers to cause a denial
    of service (crash) or execute arbitrary code via a crafted OGG file
    which triggers a heap overflow.
For the stable distribution (etch), these problems have been fixed in version
1.1.2.dfsg-1.4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1591');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libvorbis package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1591] DSA-1591-1 libvorbis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1591-1 libvorbis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libvorbis-dev', release: '4.0', reference: '1.1.2.dfsg-1.4');
deb_check(prefix: 'libvorbis0a', release: '4.0', reference: '1.1.2.dfsg-1.4');
deb_check(prefix: 'libvorbisenc2', release: '4.0', reference: '1.1.2.dfsg-1.4');
deb_check(prefix: 'libvorbisfile3', release: '4.0', reference: '1.1.2.dfsg-1.4');
deb_check(prefix: 'libvorbis', release: '4.0', reference: '1.1.2.dfsg-1.4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
