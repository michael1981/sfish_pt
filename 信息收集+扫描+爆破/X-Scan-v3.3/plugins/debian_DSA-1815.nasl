# This script was automatically generated from the dsa-1815
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39391);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1815");
 script_cve_id("CVE-2009-1760");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1815 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the Rasterbar Bittorrent library performed
insufficient validation of path names specified in torrent files, which
could lead to denial of service by overwriting files.
The old stable distribution (etch) doesn\'t include libtorrent-rasterbar.
For the stable distribution (lenny), this problem has been fixed in
version 0.13.1-2+lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1815');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libtorrent-rasterbar package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1815] DSA-1815-1 libtorrent-rasterbar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1815-1 libtorrent-rasterbar");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtorrent-rasterbar-dbg', release: '5.0', reference: '0.13.1-2+lenny1');
deb_check(prefix: 'libtorrent-rasterbar-dev', release: '5.0', reference: '0.13.1-2+lenny1');
deb_check(prefix: 'libtorrent-rasterbar-doc', release: '5.0', reference: '0.13.1-2+lenny1');
deb_check(prefix: 'libtorrent-rasterbar0', release: '5.0', reference: '0.13.1-2+lenny1');
deb_check(prefix: 'libtorrent-rasterbar', release: '5.0', reference: '0.13.1-2+lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
