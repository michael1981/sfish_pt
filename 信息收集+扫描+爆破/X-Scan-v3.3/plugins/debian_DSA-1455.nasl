# This script was automatically generated from the dsa-1455
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29902);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1455");
 script_cve_id("CVE-2007-3641", "CVE-2007-3644", "CVE-2007-3645");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1455 security update');
 script_set_attribute(attribute: 'description', value:
'Several local/remote vulnerabilities have been discovered in libarchive1,
a single library to read/write tar, cpio, pax, zip, iso9660 archives.
The Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2007-3641
  It was discovered that libarchive1 would miscompute the length of a buffer
  resulting in a buffer overflow if yet another type of corruption occurred
  in a pax extension header.
CVE-2007-3644
  It was discovered that if an archive prematurely ended within a pax
  extension header the libarchive1 library could enter an infinite loop.
CVE-2007-3645
  If an archive prematurely ended within a tar header, immediately following
  a pax extension header, libarchive1 could dereference a NULL pointer.
The old stable distribution (sarge), does not contain this package.
For the stable distribution (etch), these problems have been fixed in
version 1.2.53-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1455');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libarchive package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1455] DSA-1455-1 libarchive");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1455-1 libarchive");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bsdtar', release: '4.0', reference: '1.2.53-2etch1');
deb_check(prefix: 'libarchive-dev', release: '4.0', reference: '1.2.53-2etch1');
deb_check(prefix: 'libarchive1', release: '4.0', reference: '1.2.53-2etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
