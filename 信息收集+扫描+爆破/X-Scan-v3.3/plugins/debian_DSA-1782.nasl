# This script was automatically generated from the dsa-1782
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38641);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1782");
 script_cve_id("CVE-2008-4866", "CVE-2008-5616", "CVE-2009-0385");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1782 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in mplayer, a movie player
for Unix-like systems. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2009-0385
It was discovered that watching a malformed 4X movie file could lead to
the execution of arbitrary code.
CVE-2008-4866
It was discovered that multiple buffer overflows could lead to the
execution of arbitrary code.
CVE-2008-5616
It was discovered that watching a malformed TwinVQ file could lead to
the execution of arbitrary code.
For the oldstable distribution (etch), these problems have been fixed
in version 1.0~rc1-12etch7.
For the stable distribution (lenny), mplayer links against
ffmpeg-debian.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1782');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mplayer packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1782] DSA-1782-1 mplayer");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1782-1 mplayer");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
