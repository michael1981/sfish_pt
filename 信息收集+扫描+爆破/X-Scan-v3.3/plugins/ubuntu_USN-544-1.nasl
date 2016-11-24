# This script was automatically generated from the 544-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28251);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "544-1");
script_summary(english:"samba vulnerabilities");
script_name(english:"USN544-1 : samba vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpam-smbpass 
- libsmbclient 
- libsmbclient-dev 
- python-samba 
- python2.4-samba 
- samba 
- samba-common 
- samba-dbg 
- samba-doc 
- samba-doc-pdf 
- smbclient 
- smbfs 
- swat 
- winbind 
');
script_set_attribute(attribute:'description', value: 'Samba developers discovered that nmbd could be made to overrun a buffer
during the processing of GETDC logon server requests.  When samba is
configured as a Primary or Backup Domain Controller, a remote attacker
could send malicious logon requests and possibly cause a denial of
service. (CVE-2007-4572)

Alin Rad Pop of Secunia Research discovered that nmbd did not properly
check the length of netbios packets. When samba is configured as a WINS
server, a remote attacker could send multiple crafted requests resulting
in the execution of arbitrary code with root privileges. (CVE-2007-5398)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpam-smbpass-3.0.26a-1ubuntu2.1 (Ubuntu 7.10)
- libsmbclient-3.0.26a-1ubuntu2.1 (Ubuntu 7.10)
- libsmbclient-dev-3.0.26a-1ubuntu2.1 (Ubuntu 7.10)
- python-samba-3.0.24-2ubuntu1.3 (Ubuntu 7.04)
- python2.4-samba-3.0.22-1ubuntu4.3 (Ubuntu 6.10)
- samba-3.0.26a-1ubuntu2.1 (Ubuntu 7.10)
- samba-common-3.0.26a-1ubuntu2.1 (Ubuntu 7.10)
- samba-dbg-3.0.26a-1ubuntu2.1 (Ubuntu 7.10)
- samba-doc-3.0.26a-1ubuntu2.1 (Ubuntu 7.10)
- samba-doc-pdf-3.0.26a-1ubuntu2.1 (Ubuntu 7.10)
- smbclient-3.0.26a-1u
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-4572","CVE-2007-5398");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libpam-smbpass", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-smbpass-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpam-smbpass-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libsmbclient", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsmbclient-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsmbclient-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libsmbclient-dev", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsmbclient-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsmbclient-dev-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "python-samba", pkgver: "3.0.24-2ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-samba-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to python-samba-3.0.24-2ubuntu1.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "python2.4-samba", pkgver: "3.0.22-1ubuntu4.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-samba-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to python2.4-samba-3.0.22-1ubuntu4.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "samba", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to samba-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "samba-common", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to samba-common-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "samba-dbg", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to samba-dbg-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "samba-doc", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to samba-doc-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "samba-doc-pdf", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-doc-pdf-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to samba-doc-pdf-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "smbclient", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package smbclient-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to smbclient-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "smbfs", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package smbfs-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to smbfs-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "swat", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package swat-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to swat-3.0.26a-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "winbind", pkgver: "3.0.26a-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package winbind-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to winbind-3.0.26a-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
