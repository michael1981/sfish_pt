# This script was automatically generated from the 253-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21061);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "253-1");
script_summary(english:"heimdal vulnerability");
script_name(english:"USN253-1 : heimdal vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- heimdal-clients 
- heimdal-clients-x 
- heimdal-dev 
- heimdal-docs 
- heimdal-kdc 
- heimdal-servers 
- heimdal-servers-x 
- libasn1-6-heimdal 
- libgssapi1-heimdal 
- libhdb7-heimdal 
- libkadm5clnt4-heimdal 
- libkadm5srv7-heimdal 
- libkafs0-heimdal 
- libkrb5-17-heimdal 
');
script_set_attribute(attribute:'description', value: 'A remote Denial of Service vulnerability was discovered in the heimdal
implementation of the telnet daemon. A remote attacker could force the
server to crash due to a NULL de-reference before the user logged in,
resulting in inetd turning telnetd off because it forked too fast.

Please note that the heimdal-servers package is not officially
supported in Ubuntu (it is in the \'universe\' component of the
archive). However, this affects you if you use a customized version
built from the heimdal source package (which is supported).');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- heimdal-clients-0.6.3-11ubuntu1.2 (Ubuntu 5.10)
- heimdal-clients-x-0.6.3-11ubuntu1.2 (Ubuntu 5.10)
- heimdal-dev-0.6.3-11ubuntu1.2 (Ubuntu 5.10)
- heimdal-docs-0.6.3-11ubuntu1.2 (Ubuntu 5.10)
- heimdal-kdc-0.6.3-11ubuntu1.2 (Ubuntu 5.10)
- heimdal-servers-0.6.3-11ubuntu1.2 (Ubuntu 5.10)
- heimdal-servers-x-0.6.3-11ubuntu1.2 (Ubuntu 5.10)
- libasn1-6-heimdal-0.6.3-11ubuntu1.2 (Ubuntu 5.10)
- libgssapi1-heimdal-0.6.3-11ubuntu1.2 (Ubuntu 5.10)
- libhdb7-heimdal-0.6.3-11ubuntu1.2 (Ubuntu 5.10)
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-0677");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "heimdal-clients", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package heimdal-clients-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to heimdal-clients-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "heimdal-clients-x", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package heimdal-clients-x-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to heimdal-clients-x-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "heimdal-dev", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package heimdal-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to heimdal-dev-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "heimdal-docs", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package heimdal-docs-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to heimdal-docs-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "heimdal-kdc", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package heimdal-kdc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to heimdal-kdc-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "heimdal-servers", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package heimdal-servers-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to heimdal-servers-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "heimdal-servers-x", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package heimdal-servers-x-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to heimdal-servers-x-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libasn1-6-heimdal", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libasn1-6-heimdal-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libasn1-6-heimdal-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgssapi1-heimdal", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgssapi1-heimdal-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgssapi1-heimdal-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libhdb7-heimdal", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libhdb7-heimdal-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libhdb7-heimdal-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkadm5clnt4-heimdal", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkadm5clnt4-heimdal-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkadm5clnt4-heimdal-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkadm5srv7-heimdal", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkadm5srv7-heimdal-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkadm5srv7-heimdal-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkafs0-heimdal", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkafs0-heimdal-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkafs0-heimdal-0.6.3-11ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkrb5-17-heimdal", pkgver: "0.6.3-11ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkrb5-17-heimdal-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkrb5-17-heimdal-0.6.3-11ubuntu1.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
