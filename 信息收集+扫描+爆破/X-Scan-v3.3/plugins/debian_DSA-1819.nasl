# This script was automatically generated from the dsa-1819
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39451);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1819");
 script_cve_id("CVE-2008-1768", "CVE-2008-1769", "CVE-2008-1881", "CVE-2008-2147", "CVE-2008-2430", "CVE-2008-3794", "CVE-2008-4686");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1819 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in vlc, a multimedia player
and streamer. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2008-1768
Drew Yao discovered that multiple integer overflows in the MP4 demuxer,
Real demuxer and Cinepak codec can lead to the execution of arbitrary
code.
CVE-2008-1769
Drew Yao discovered that the Cinepak codec is prone to a memory
corruption, which can be triggered by a crafted Cinepak file.
CVE-2008-1881
Luigi Auriemma discovered that it is possible to execute arbitrary code
via a long subtitle in an SSA file.
CVE-2008-2147
It was discovered that vlc is prone to a search path vulnerability,
which allows local users to perform privilege escalations.
CVE-2008-2430
Alin Rad Pop discovered that it is possible to execute arbitrary code
when opening a WAV file containing a large fmt chunk.
CVE-2008-3794
Pınar Yanardağ discovered that it is possible to execute arbitrary code
when opening a crafted mmst link.
CVE-2008-4686
Tobias Klein discovered that it is possible to execute arbitrary code
when opening a crafted .ty file.
CVE-2008-5032
Tobias Klein discovered that it is possible to execute arbitrary code
when opening an invalid CUE image file with a crafted header.
For the oldstable distribution (etch), these problems have been fixed
in version 0.8.6-svn20061012.debian-5.1+etch3.
For the stable distribution (lenny), these problems have been fixed in
version 0.8.6.h-4+lenny2, which was already included in the lenny
release.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1819');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your vlc packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1819] DSA-1819-1 vlc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1819-1 vlc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libvlc0', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'libvlc0-dev', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'mozilla-plugin-vlc', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'vlc', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'vlc-nox', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'vlc-plugin-alsa', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'vlc-plugin-arts', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'vlc-plugin-esd', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'vlc-plugin-ggi', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'vlc-plugin-glide', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'vlc-plugin-sdl', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'vlc-plugin-svgalib', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
deb_check(prefix: 'wxvlc', release: '4.0', reference: '0.8.6-svn20061012.debian-5.1+etch3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
