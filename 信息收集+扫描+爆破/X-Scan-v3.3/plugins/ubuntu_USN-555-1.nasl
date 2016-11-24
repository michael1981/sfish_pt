# This script was automatically generated from the 555-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29305);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "555-1");
script_summary(english:"e2fsprogs vulnerability");
script_name(english:"USN555-1 : e2fsprogs vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- comerr-dev 
- e2fsck-static 
- e2fslibs 
- e2fslibs-dev 
- e2fsprogs 
- libblkid-dev 
- libblkid1 
- libcomerr2 
- libss2 
- libuuid1 
- ss-dev 
- uuid-dev 
');
script_set_attribute(attribute:'description', value: 'Rafal Wojtczuk discovered multiple integer overflows in e2fsprogs.  If a
user or automated system were tricked into fscking a malicious ext2/ext3
filesystem, a remote attacker could execute arbitrary code with the user\'s
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- comerr-dev-2.1-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
- e2fsck-static-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
- e2fslibs-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
- e2fslibs-dev-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
- e2fsprogs-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
- libblkid-dev-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
- libblkid1-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
- libcomerr2-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
- libss2-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
- libuuid1-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
- ss-dev-2.0-1.40.2-1ubuntu1.1 (Ubuntu 7.10)
-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2007-5497");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "comerr-dev", pkgver: "2.1-1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package comerr-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to comerr-dev-2.1-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "e2fsck-static", pkgver: "1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package e2fsck-static-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to e2fsck-static-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "e2fslibs", pkgver: "1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package e2fslibs-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to e2fslibs-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "e2fslibs-dev", pkgver: "1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package e2fslibs-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to e2fslibs-dev-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "e2fsprogs", pkgver: "1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package e2fsprogs-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to e2fsprogs-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libblkid-dev", pkgver: "1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libblkid-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libblkid-dev-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libblkid1", pkgver: "1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libblkid1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libblkid1-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcomerr2", pkgver: "1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcomerr2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcomerr2-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libss2", pkgver: "1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libss2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libss2-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libuuid1", pkgver: "1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libuuid1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libuuid1-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ss-dev", pkgver: "2.0-1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ss-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ss-dev-2.0-1.40.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "uuid-dev", pkgver: "1.2-1.40.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package uuid-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to uuid-dev-1.2-1.40.2-1ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
