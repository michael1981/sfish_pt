# This script was automatically generated from the dsa-1471
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30063);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1471");
 script_cve_id("CVE-2007-3106", "CVE-2007-4029", "CVE-2007-4066");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1471 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities were found in the Vorbis General Audio
Compression Codec, which may lead to denial of service or the
execution of arbitrary code, if a user is tricked into opening
a malformed Ogg Audio file with an application linked against
libvorbis.
For the old stable distribution (sarge), these problems have been fixed
in version 1.1.0-2.
For the stable distribution (etch), these problems have been fixed in
version 1.1.2.dfsg-1.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1471');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libvorbis packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1471] DSA-1471-1 libvorbis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1471-1 libvorbis");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libvorbis-dev', release: '3.1', reference: '1.1.0-2');
deb_check(prefix: 'libvorbis0a', release: '3.1', reference: '1.1.0-2');
deb_check(prefix: 'libvorbisenc2', release: '3.1', reference: '1.1.0-2');
deb_check(prefix: 'libvorbisfile3', release: '3.1', reference: '1.1.0-2');
deb_check(prefix: 'libvorbis-dev', release: '4.0', reference: '1.1.2.dfsg-1.3');
deb_check(prefix: 'libvorbis0a', release: '4.0', reference: '1.1.2.dfsg-1.3');
deb_check(prefix: 'libvorbisenc2', release: '4.0', reference: '1.1.2.dfsg-1.3');
deb_check(prefix: 'libvorbisfile3', release: '4.0', reference: '1.1.2.dfsg-1.3');
deb_check(prefix: 'libvorbis', release: '4.0', reference: '1.1.2.dfsg-1.3');
deb_check(prefix: 'libvorbis', release: '3.1', reference: '1.1.0-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
