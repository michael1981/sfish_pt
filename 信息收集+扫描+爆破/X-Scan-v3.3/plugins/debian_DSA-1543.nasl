# This script was automatically generated from the dsa-1543
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31949);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1543");
 script_cve_id("CVE-2007-6681", "CVE-2007-6682", "CVE-2007-6683", "CVE-2008-0073", "CVE-2008-0295", "CVE-2008-0296", "CVE-2008-0984");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1543 security update');
 script_set_attribute(attribute: 'description', value:
'Luigi Auriemma, Alin Rad Pop, R&eacute;mi Denis-Courmont, Quovodis, Guido
Landi, Felipe Manzano, Anibal Sacco and others discovered multiple
vulnerabilities in vlc, an application for playback and streaming of
audio and video.  In the worst case, these weaknesses permit a remote,
unauthenticated attacker to execute arbitrary code with the privileges
of the user running vlc.
The Common Vulnerabilities and Exposures project identifies the
following eight problems:
CVE-2007-6681
    A buffer overflow vulnerability in subtitle handling allows an
    attacker to execute arbitrary code through the opening of a
    maliciously crafted MicroDVD, SSA or Vplayer file.
CVE-2007-6682
    A format string vulnerability in the HTTP-based remote control
    facility of the vlc application allows a remote, unauthenticated
    attacker to execute arbitrary code.
CVE-2007-6683
    Insecure argument validation allows a remote attacker to overwrite
    arbitrary files writable by the user running vlc, if a maliciously
    crafted M3U playlist or MP3 audio file is opened.
    Heap buffer overflows in RTSP stream and session description
    protocol (SDP) handling allow an attacker to execute arbitrary
    code if a maliciously crafted RTSP stream is played.
CVE-2008-0073
    Insufficient integer bounds checking in SDP handling allows the
    execution of arbitrary code through a maliciously crafted SDP
    stream ID parameter in an RTSP stream.
CVE-2008-0984
    Insufficient integrity checking in the MP4 demuxer allows a remote
    attacker to overwrite arbitrary memory and execute arbitrary code
    if a maliciously crafted MP4 file is opened.
CVE-2008-1489
    An integer overflow vulnerability in MP4 handling allows a remote
    attacker to cause a heap buffer overflow, inducing a crash and
    possibly the execution of arbitrary code if a maliciously crafted
    MP4 file is opened.
For the stable distribution (etch), these problems have been fixed in
version 0.8.6-svn20061012.debian-5.1+etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1543');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your vlc packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1543] DSA-1543-1 vlc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1543-1 vlc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libvlc0', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'libvlc0-dev', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'mozilla-plugin-vlc', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'vlc', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'vlc-nox', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'vlc-plugin-alsa', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'vlc-plugin-arts', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'vlc-plugin-esd', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'vlc-plugin-ggi', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'vlc-plugin-glide', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'vlc-plugin-sdl', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'vlc-plugin-svgalib', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
deb_check(prefix: 'wxvlc', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
