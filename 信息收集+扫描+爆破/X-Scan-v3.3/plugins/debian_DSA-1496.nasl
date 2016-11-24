# This script was automatically generated from the dsa-1496
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(31056);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1496");
 script_cve_id("CVE-2008-0485", "CVE-2008-0486", "CVE-2008-0629", "CVE-2008-0630");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1496 security update');
 script_set_attribute(attribute: 'description', value:
'Several buffer overflows have been discovered in the MPlayer movie player,
which might lead to the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2008-0485
    Felipe Manzano and Anibal Sacco discovered a buffer overflow in
    the demuxer for MOV files.
CVE-2008-0486
    Reimar Doeffinger discovered a buffer overflow in the FLAC header
    parsing.
CVE-2008-0629
    Adam Bozanich discovered a buffer overflow in the CDDB access code.
CVE-2008-0630
    Adam Bozanich discovered a buffer overflow in URL parsing.
The old stable distribution (sarge) doesn\'t contain mplayer.
For the stable distribution (etch), these problems have been fixed in
version 1.0~rc1-12etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1496');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mplayer packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1496] DSA-1496-1 mplayer");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1496-1 mplayer");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
