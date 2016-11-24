# This script was automatically generated from the dsa-1583
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32405);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1583");
 script_cve_id("CVE-2007-6454", "CVE-2008-2040");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1583 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in GNOME PeerCast,
the GNOME interface to PeerCast, a P2P audio and video streaming
server. The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2007-6454
    Luigi Auriemma discovered that PeerCast is vulnerable to a heap
    overflow in the HTTP server code, which allows remote attackers to
    cause a denial of service and possibly execute arbitrary code via a
    long SOURCE request.
CVE-2008-2040
    Nico Golde discovered that PeerCast, a P2P audio and video streaming
    server, is vulnerable to a buffer overflow in the HTTP Basic
    Authentication code, allowing a remote attacker to crash PeerCast or
    execute arbitrary code.
For the stable distribution (etch), these problems have been fixed in
version 0.5.4-1.1etch0.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1583');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnome-peercast package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1583] DSA-1583-1 gnome-peercast");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1583-1 gnome-peercast");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnome-peercast', release: '4.0', reference: '0.5.4-1.1etch0');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
