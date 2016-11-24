# This script was automatically generated from the 29-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20644);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "29-1");
script_summary(english:"samba vulnerability");
script_name(english:"USN29-1 : samba vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpam-smbpass 
- libsmbclient 
- libsmbclient-dev 
- python2.3-samba 
- samba 
- samba-common 
- samba-doc 
- smbclient 
- smbfs 
- swat 
- winbind 
');
script_set_attribute(attribute:'description', value: 'During an audit of the Samba 3.x code base Stefan Esser discovered a
Unicode file name buffer overflow within the handling of
TRANSACT2_QFILEPATHINFO replies. A malicious samba user with write
access to a share could exploit this by creating specially crafted
path names (files with very long names containing Unicode characters)
that would overflow an internal buffer and could lead to remote
execution of arbitrary code with the privileges of the samba server.

Since the samba server usually (by default) runs as root, this flaw
can lead to privilege escalation and unbounded system compromise.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpam-smbpass-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
- libsmbclient-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
- libsmbclient-dev-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
- python2.3-samba-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
- samba-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
- samba-common-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
- samba-doc-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
- smbclient-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
- smbfs-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
- swat-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
- winbind-3.0.7-1ubuntu6.2 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2004-0882");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "libpam-smbpass", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-smbpass-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpam-smbpass-3.0.7-1ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libsmbclient", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsmbclient-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libsmbclient-3.0.7-1ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libsmbclient-dev", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsmbclient-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libsmbclient-dev-3.0.7-1ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "python2.3-samba", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-samba-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to python2.3-samba-3.0.7-1ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "samba", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to samba-3.0.7-1ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "samba-common", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to samba-common-3.0.7-1ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "samba-doc", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to samba-doc-3.0.7-1ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "smbclient", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package smbclient-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to smbclient-3.0.7-1ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "smbfs", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package smbfs-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to smbfs-3.0.7-1ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "swat", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package swat-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to swat-3.0.7-1ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "winbind", pkgver: "3.0.7-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package winbind-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to winbind-3.0.7-1ubuntu6.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
