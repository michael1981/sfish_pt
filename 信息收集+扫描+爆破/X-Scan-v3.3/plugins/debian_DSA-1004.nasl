# This script was automatically generated from the dsa-1004
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22546);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1004");
 script_cve_id("CVE-2005-4048");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1004 security update');
 script_set_attribute(attribute: 'description', value:
'Simon Kilvington discovered that specially crafted PNG images can trigger
a heap overflow in libavcodec, the multimedia library of ffmpeg, which may
lead to the execution of arbitrary code.
The vlc media player links statically against libavcodec.
The old stable distribution (woody) isn\'t affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.8.1.svn20050314-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1004');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your vlc package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1004] DSA-1004-1 vlc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1004-1 vlc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnome-vlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'gvlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'kvlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'libvlc0-dev', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'mozilla-plugin-vlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'qvlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-alsa', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-esd', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-ggi', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-glide', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-gnome', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-gtk', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-plugin-alsa', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-plugin-arts', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-plugin-esd', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-plugin-ggi', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-plugin-glide', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-plugin-sdl', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-plugin-svgalib', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-qt', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'vlc-sdl', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
deb_check(prefix: 'wxvlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
