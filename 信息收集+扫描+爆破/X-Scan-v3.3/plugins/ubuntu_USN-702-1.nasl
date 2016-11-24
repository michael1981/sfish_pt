# This script was automatically generated from the 702-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37362);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "702-1");
script_summary(english:"samba vulnerability");
script_name(english:"USN702-1 : samba vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpam-smbpass 
- libsmbclient 
- libsmbclient-dev 
- libwbclient0 
- samba 
- samba-common 
- samba-dbg 
- samba-doc 
- samba-doc-pdf 
- samba-tools 
- smbclient 
- smbfs 
- swat 
- winbind 
');
script_set_attribute(attribute:'description', value: 'Gunter Höckel discovered that Samba with registry shares enabled did not
properly validate share names. An authenticated user could gain access to the
root filesystem by using an older version of smbclient and specifying an
empty string as a share name. This is only an issue if registry shares are
enabled on the server by setting "registry shares = yes", "include = registry",
or "config backend = registry", which is not the default.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpam-smbpass-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
- libsmbclient-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
- libsmbclient-dev-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
- libwbclient0-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
- samba-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
- samba-common-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
- samba-dbg-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
- samba-doc-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
- samba-doc-pdf-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
- samba-tools-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
- smbclient-3.2.3-1ubuntu3.4 (Ubuntu 8.10)
-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:C/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2009-0022");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libpam-smbpass", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-smbpass-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpam-smbpass-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libsmbclient", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsmbclient-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libsmbclient-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libsmbclient-dev", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsmbclient-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libsmbclient-dev-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libwbclient0", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwbclient0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libwbclient0-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "samba", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to samba-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "samba-common", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-common-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to samba-common-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "samba-dbg", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to samba-dbg-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "samba-doc", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to samba-doc-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "samba-doc-pdf", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-doc-pdf-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to samba-doc-pdf-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "samba-tools", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-tools-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to samba-tools-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "smbclient", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package smbclient-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to smbclient-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "smbfs", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package smbfs-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to smbfs-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "swat", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package swat-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to swat-3.2.3-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "winbind", pkgver: "3.2.3-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package winbind-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to winbind-3.2.3-1ubuntu3.4
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
