# This script was automatically generated from the 580-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31165);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "580-1");
script_summary(english:"libcdio vulnerability");
script_name(english:"USN580-1 : libcdio vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libcdio-cdda-dev 
- libcdio-cdda0 
- libcdio-dev 
- libcdio-paranoia-dev 
- libcdio-paranoia0 
- libcdio6 
- libiso9660-4 
- libiso9660-dev 
');
script_set_attribute(attribute:'description', value: 'Devon Miller discovered that the iso-info and cd-info tools did not
properly perform bounds checking. If a user were tricked into using
these tools with a crafted iso image, an attacker could cause a
denial of service via a core dump, and possibly execute arbitrary
code.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libcdio-cdda-dev-0.76-1ubuntu2.7.10.1 (Ubuntu 7.10)
- libcdio-cdda0-0.76-1ubuntu2.7.10.1 (Ubuntu 7.10)
- libcdio-dev-0.76-1ubuntu2.7.10.1 (Ubuntu 7.10)
- libcdio-paranoia-dev-0.76-1ubuntu2.7.10.1 (Ubuntu 7.10)
- libcdio-paranoia0-0.76-1ubuntu2.7.10.1 (Ubuntu 7.10)
- libcdio6-0.76-1ubuntu2.7.10.1 (Ubuntu 7.10)
- libiso9660-4-0.76-1ubuntu2.7.10.1 (Ubuntu 7.10)
- libiso9660-dev-0.76-1ubuntu2.7.10.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-6613");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libcdio-cdda-dev", pkgver: "0.76-1ubuntu2.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcdio-cdda-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcdio-cdda-dev-0.76-1ubuntu2.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcdio-cdda0", pkgver: "0.76-1ubuntu2.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcdio-cdda0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcdio-cdda0-0.76-1ubuntu2.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcdio-dev", pkgver: "0.76-1ubuntu2.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcdio-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcdio-dev-0.76-1ubuntu2.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcdio-paranoia-dev", pkgver: "0.76-1ubuntu2.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcdio-paranoia-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcdio-paranoia-dev-0.76-1ubuntu2.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcdio-paranoia0", pkgver: "0.76-1ubuntu2.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcdio-paranoia0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcdio-paranoia0-0.76-1ubuntu2.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcdio6", pkgver: "0.76-1ubuntu2.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcdio6-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcdio6-0.76-1ubuntu2.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libiso9660-4", pkgver: "0.76-1ubuntu2.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libiso9660-4-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libiso9660-4-0.76-1ubuntu2.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libiso9660-dev", pkgver: "0.76-1ubuntu2.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libiso9660-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libiso9660-dev-0.76-1ubuntu2.7.10.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
