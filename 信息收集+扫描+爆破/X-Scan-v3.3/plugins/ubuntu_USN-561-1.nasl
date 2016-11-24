# This script was automatically generated from the 561-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29917);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "561-1");
script_summary(english:"pwlib vulnerability");
script_name(english:"USN561-1 : pwlib vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpt-1.10.0 
- libpt-dbg 
- libpt-dev 
- libpt-doc 
- libpt-plugins-alsa 
- libpt-plugins-avc 
- libpt-plugins-dc 
- libpt-plugins-oss 
- libpt-plugins-v4l 
- libpt-plugins-v4l2 
');
script_set_attribute(attribute:'description', value: 'Jose Miguel Esparza discovered that pwlib did not correctly handle large
string lengths.  A remote attacker could send specially crafted packets to
applications linked against pwlib (e.g. Ekiga) causing them to crash, leading
to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpt-1.10.0-1.10.10-0ubuntu2.1 (Ubuntu 7.10)
- libpt-dbg-1.10.10-0ubuntu2.1 (Ubuntu 7.10)
- libpt-dev-1.10.10-0ubuntu2.1 (Ubuntu 7.10)
- libpt-doc-1.10.10-0ubuntu2.1 (Ubuntu 7.10)
- libpt-plugins-alsa-1.10.10-0ubuntu2.1 (Ubuntu 7.10)
- libpt-plugins-avc-1.10.10-0ubuntu2.1 (Ubuntu 7.10)
- libpt-plugins-dc-1.10.10-0ubuntu2.1 (Ubuntu 7.10)
- libpt-plugins-oss-1.10.10-0ubuntu2.1 (Ubuntu 7.10)
- libpt-plugins-v4l-1.10.10-0ubuntu2.1 (Ubuntu 7.10)
- libpt-plugins-v4l2-1.10.10-0ubuntu2.1 (Ubuntu 7
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-4897");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libpt-1.10.0", pkgver: "1.10.10-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpt-1.10.0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpt-1.10.0-1.10.10-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpt-dbg", pkgver: "1.10.10-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpt-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpt-dbg-1.10.10-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpt-dev", pkgver: "1.10.10-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpt-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpt-dev-1.10.10-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpt-doc", pkgver: "1.10.10-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpt-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpt-doc-1.10.10-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpt-plugins-alsa", pkgver: "1.10.10-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpt-plugins-alsa-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpt-plugins-alsa-1.10.10-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpt-plugins-avc", pkgver: "1.10.10-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpt-plugins-avc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpt-plugins-avc-1.10.10-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpt-plugins-dc", pkgver: "1.10.10-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpt-plugins-dc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpt-plugins-dc-1.10.10-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpt-plugins-oss", pkgver: "1.10.10-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpt-plugins-oss-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpt-plugins-oss-1.10.10-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpt-plugins-v4l", pkgver: "1.10.10-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpt-plugins-v4l-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpt-plugins-v4l-1.10.10-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpt-plugins-v4l2", pkgver: "1.10.10-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpt-plugins-v4l2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpt-plugins-v4l2-1.10.10-0ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
