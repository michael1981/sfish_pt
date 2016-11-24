# This script was automatically generated from the 165-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20571);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "165-1");
script_summary(english:"heartbeat vulnerability");
script_name(english:"USN165-1 : heartbeat vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- heartbeat 
- heartbeat-dev 
- ldirectord 
- libpils-dev 
- libpils0 
- libstonith-dev 
- libstonith0 
- stonith 
');
script_set_attribute(attribute:'description', value: 'Eric Romang discovered that heartbeat created temporary files in an
insecure manner. This could allow a symlink attack to create or
overwrite arbitrary files with root privileges as soon as heartbeat is
started.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- heartbeat-1.2.3-3ubuntu1.1 (Ubuntu 5.04)
- heartbeat-dev-1.2.3-3ubuntu1.1 (Ubuntu 5.04)
- ldirectord-1.2.3-3ubuntu1.1 (Ubuntu 5.04)
- libpils-dev-1.2.3-3ubuntu1.1 (Ubuntu 5.04)
- libpils0-1.2.3-3ubuntu1.1 (Ubuntu 5.04)
- libstonith-dev-1.2.3-3ubuntu1.1 (Ubuntu 5.04)
- libstonith0-1.2.3-3ubuntu1.1 (Ubuntu 5.04)
- stonith-1.2.3-3ubuntu1.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2005-2231");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "heartbeat", pkgver: "1.2.3-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package heartbeat-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to heartbeat-1.2.3-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "heartbeat-dev", pkgver: "1.2.3-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package heartbeat-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to heartbeat-dev-1.2.3-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "ldirectord", pkgver: "1.2.3-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ldirectord-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ldirectord-1.2.3-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpils-dev", pkgver: "1.2.3-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpils-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpils-dev-1.2.3-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpils0", pkgver: "1.2.3-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpils0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpils0-1.2.3-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libstonith-dev", pkgver: "1.2.3-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libstonith-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libstonith-dev-1.2.3-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libstonith0", pkgver: "1.2.3-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libstonith0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libstonith0-1.2.3-3ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "stonith", pkgver: "1.2.3-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package stonith-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to stonith-1.2.3-3ubuntu1.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
