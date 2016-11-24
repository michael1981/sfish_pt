# This script was automatically generated from the 839-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(41968);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "839-1");
script_summary(english:"samba vulnerabilities");
script_name(english:"USN839-1 : samba vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpam-smbpass 
- libsmbclient 
- libsmbclient-dev 
- libwbclient0 
- python2.4-samba 
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
script_set_attribute(attribute:'description', value: 'J. David Hester discovered that Samba incorrectly handled users that lack
home directories when the automated [homes] share is enabled. An
authenticated user could connect to that share name and gain access to the
whole filesystem. (CVE-2009-2813)

Tim Prouty discovered that the smbd daemon in Samba incorrectly handled
certain unexpected network replies. A remote attacker could send malicious
replies to the server and cause smbd to use all available CPU, leading to a
denial of service. (CVE-2009-2906)

Ronald Volgers discovered that the mount.cifs utility, when installed as a
setuid program, would not verify user permissions before opening a
credentials file. A local user could exploit this to use or read the
contents of unauthorized credential files. (CVE-2009-2948)

Reinhard Nißl discovered that the smbclient utility contained format string
vulnerabilities in its file name handling. Because of security features in
Ubuntu, exploitation of this vulnerability is limited. If a user or
automated system were tr
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpam-smbpass-3.3.2-1ubuntu3.2 (Ubuntu 9.04)
- libsmbclient-3.3.2-1ubuntu3.2 (Ubuntu 9.04)
- libsmbclient-dev-3.3.2-1ubuntu3.2 (Ubuntu 9.04)
- libwbclient0-3.3.2-1ubuntu3.2 (Ubuntu 9.04)
- python2.4-samba-3.0.22-1ubuntu3.9 (Ubuntu 6.06)
- samba-3.3.2-1ubuntu3.2 (Ubuntu 9.04)
- samba-common-3.3.2-1ubuntu3.2 (Ubuntu 9.04)
- samba-dbg-3.3.2-1ubuntu3.2 (Ubuntu 9.04)
- samba-doc-3.3.2-1ubuntu3.2 (Ubuntu 9.04)
- samba-doc-pdf-3.3.2-1ubuntu3.2 (Ubuntu 9.04)
- samba-tools-3.3.2-1ubuntu3.2 (Ubuntu 
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1886","CVE-2009-1888","CVE-2009-2813","CVE-2009-2906","CVE-2009-2948");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libpam-smbpass", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-smbpass-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpam-smbpass-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsmbclient", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsmbclient-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsmbclient-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsmbclient-dev", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsmbclient-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsmbclient-dev-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libwbclient0", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwbclient0-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libwbclient0-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-samba", pkgver: "3.0.22-1ubuntu3.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-samba-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-samba-3.0.22-1ubuntu3.9
');
}
found = ubuntu_check(osver: "9.04", pkgname: "samba", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to samba-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "samba-common", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to samba-common-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "samba-dbg", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to samba-dbg-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "samba-doc", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to samba-doc-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "samba-doc-pdf", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-doc-pdf-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to samba-doc-pdf-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "samba-tools", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-tools-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to samba-tools-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "smbclient", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package smbclient-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to smbclient-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "smbfs", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package smbfs-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to smbfs-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "swat", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package swat-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to swat-3.3.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "winbind", pkgver: "3.3.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package winbind-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to winbind-3.3.2-1ubuntu3.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
