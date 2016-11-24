# This script was automatically generated from the 611-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32192);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "611-2");
script_summary(english:"vorbis-tools vulnerability");
script_name(english:"USN611-2 : vorbis-tools vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "vorbis-tools" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-611-1 fixed a vulnerability in Speex. This update provides the
corresponding update for ogg123, part of vorbis-tools.

Original advisory details:

 It was discovered that Speex did not properly validate its input when
 processing Speex file headers. If a user or automated system were
 tricked into opening a specially crafted Speex file, an attacker could
 create a denial of service in applications linked against Speex or
 possibly execute arbitrary code as the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- vorbis-tools-1.1.1-15ubuntu0.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1686");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "vorbis-tools", pkgver: "1.1.1-15ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vorbis-tools-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to vorbis-tools-1.1.1-15ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
