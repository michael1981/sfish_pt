# This script was automatically generated from the dsa-1536
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31721);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1536");
 script_cve_id("CVE-2007-1246", "CVE-2007-1387", "CVE-2008-0073", "CVE-2008-0486", "CVE-2008-1161");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1536 security update');
 script_set_attribute(attribute: 'description', value:
'Several local vulnerabilities have been discovered in Xine, a
media player library, allowed for a denial of service or arbitrary code
execution, which could be exploited through viewing malicious content.
The Common Vulnerabilities and Exposures project identifies the following
problems:
    The DMO_VideoDecoder_Open function does not set the biSize before use in a
    memcpy, which allows user-assisted remote attackers to cause a buffer overflow
    and possibly execute arbitrary code (applies to sarge only).
CVE-2008-0073
    Array index error in the sdpplin_parse function allows remote RTSP servers
    to execute arbitrary code via a large streamid SDP parameter.
CVE-2008-0486
    Array index vulnerability in libmpdemux/demux_audio.c might allow remote
    attackers to execute arbitrary code via a crafted FLAC tag, which triggers
    a buffer overflow (applies to etch only).
CVE-2008-1161
    Buffer overflow in the Matroska demuxer allows remote attackers to cause a
    denial of service (crash) and possibly execute arbitrary code via a Matroska
    file with invalid frame sizes.
For the old stable distribution (sarge), these problems have been fixed in
version 1.0.1-1sarge7.
For the stable distribution (etch), these problems have been fixed in version
1.1.2+dfsg-6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1536');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xine-lib package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1536] DSA-1536-1 libxine");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1536-1 libxine");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libxine-dev', release: '3.1', reference: '1.0.1-1sarge7');
deb_check(prefix: 'libxine1', release: '3.1', reference: '1.0.1-1sarge7');
deb_check(prefix: 'libxine-dev', release: '4.0', reference: '1.1.2+dfsg-6');
deb_check(prefix: 'libxine1', release: '4.0', reference: '1.1.2+dfsg-6');
deb_check(prefix: 'libxine1-dbg', release: '4.0', reference: '1.1.2+dfsg-6');
deb_check(prefix: 'xine-lib', release: '4.0', reference: '1.1.2+dfsg-6');
deb_check(prefix: 'xine-lib', release: '3.1', reference: '1.0.1-1sarge7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
