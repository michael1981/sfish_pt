# This script was automatically generated from the 314-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27890);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "314-1");
script_summary(english:"samba vulnerability");
script_name(english:"USN314-1 : samba vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpam-smbpass 
- libsmbclient 
- libsmbclient-dev 
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
script_set_attribute(attribute:'description', value: 'The Samba security team reported a Denial of Service vulnerability in
the handling of information about active connections. In certain
circumstances an attacker could continually increase the memory usage
of the  smbd process by issuing a large number of share connection
requests. By draining all available memory, this could be exploited to
render the remote Samba server unusable.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpam-smbpass-3.0.22-1ubuntu3.1 (Ubuntu 6.06)
- libsmbclient-3.0.22-1ubuntu3.1 (Ubuntu 6.06)
- libsmbclient-dev-3.0.22-1ubuntu3.1 (Ubuntu 6.06)
- python2.4-samba-3.0.22-1ubuntu3.1 (Ubuntu 6.06)
- samba-3.0.22-1ubuntu3.1 (Ubuntu 6.06)
- samba-common-3.0.22-1ubuntu3.1 (Ubuntu 6.06)
- samba-dbg-3.0.22-1ubuntu3.1 (Ubuntu 6.06)
- samba-doc-3.0.22-1ubuntu3.1 (Ubuntu 6.06)
- samba-doc-pdf-3.0.22-1ubuntu3.1 (Ubuntu 6.06)
- smbclient-3.0.22-1ubuntu3.1 (Ubuntu 6.06)
- smbfs-3.0.22-1ubuntu3.1 (Ubuntu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-3403");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libpam-smbpass", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-smbpass-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpam-smbpass-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsmbclient", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsmbclient-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsmbclient-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsmbclient-dev", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsmbclient-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsmbclient-dev-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-samba", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-samba-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-samba-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "samba", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to samba-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "samba-common", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to samba-common-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "samba-dbg", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to samba-dbg-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "samba-doc", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to samba-doc-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "samba-doc-pdf", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package samba-doc-pdf-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to samba-doc-pdf-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "smbclient", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package smbclient-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to smbclient-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "smbfs", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package smbfs-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to smbfs-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "swat", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package swat-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to swat-3.0.22-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "winbind", pkgver: "3.0.22-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package winbind-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to winbind-3.0.22-1ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
