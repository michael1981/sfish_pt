# This script was automatically generated from the 683-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36374);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "683-1");
script_summary(english:"imlib2 vulnerability");
script_name(english:"USN683-1 : imlib2 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libimlib2 
- libimlib2-dev 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Imlib2 did not correctly handle certain malformed
XPM images. If a user were tricked into opening a specially crafted image
with an application that uses Imlib2, an attacker could cause a denial of
service and possibly execute arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libimlib2-1.4.0-1.1ubuntu1.1 (Ubuntu 8.10)
- libimlib2-dev-1.4.0-1.1ubuntu1.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-5187");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libimlib2", pkgver: "1.4.0-1.1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libimlib2-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libimlib2-1.4.0-1.1ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libimlib2-dev", pkgver: "1.4.0-1.1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libimlib2-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libimlib2-dev-1.4.0-1.1ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
