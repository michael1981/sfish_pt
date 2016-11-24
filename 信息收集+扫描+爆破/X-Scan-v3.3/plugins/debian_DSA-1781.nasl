# This script was automatically generated from the dsa-1781
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38640);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1781");
 script_cve_id("CVE-2008-3162", "CVE-2009-0385");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1781 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in ffmpeg, a multimedia
player, server and encoder. The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2009-0385
It was discovered that watching a malformed 4X movie file could lead to
the execution of arbitrary code.
CVE-2008-3162
It was discovered that using a crafted STR file can lead to the
execution of arbitrary code.
For the oldstable distribution (etch), these problems have been fixed
in version 0.cvs20060823-8+etch1.
For the stable distribution (lenny), these problems have been fixed in
version 0.svn20080206-17+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1781');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ffmpeg-debian packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1781] DSA-1781-1 ffmpeg-debian");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1781-1 ffmpeg-debian");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ffmpeg', release: '4.0', reference: '0.cvs20060823-8+etch1');
deb_check(prefix: 'libavcodec-dev', release: '4.0', reference: '0.cvs20060823-8+etch1');
deb_check(prefix: 'libavcodec0d', release: '4.0', reference: '0.cvs20060823-8+etch1');
deb_check(prefix: 'libavformat-dev', release: '4.0', reference: '0.cvs20060823-8+etch1');
deb_check(prefix: 'libavformat0d', release: '4.0', reference: '0.cvs20060823-8+etch1');
deb_check(prefix: 'libpostproc-dev', release: '4.0', reference: '0.cvs20060823-8+etch1');
deb_check(prefix: 'libpostproc0d', release: '4.0', reference: '0.cvs20060823-8+etch1');
deb_check(prefix: 'ffmpeg', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'ffmpeg-dbg', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'ffmpeg-doc', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libavcodec-dev', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libavcodec51', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libavdevice-dev', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libavdevice52', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libavformat-dev', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libavformat52', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libavutil-dev', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libavutil49', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libpostproc-dev', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libpostproc51', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libswscale-dev', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'libswscale0', release: '5.0', reference: '0.svn20080206-17+lenny1');
deb_check(prefix: 'ffmpeg-debian', release: '4.0', reference: '0.cvs20060823-8+etch1');
deb_check(prefix: 'ffmpeg-debian', release: '5.0', reference: '0.svn20080206-17+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
