# This script was automatically generated from the 355-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27935);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "355-1");
script_summary(english:"openssh vulnerabilities");
script_name(english:"USN355-1 : openssh vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- openssh-client 
- openssh-server 
- ssh 
- ssh-askpass-gnome 
');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy discovered that the SSH daemon did not properly handle
authentication packets with duplicated blocks. By sending specially
crafted packets, a remote attacker could exploit this to cause the ssh
daemon to drain all available CPU resources until the login grace time
expired. (CVE-2006-4924)

Mark Dowd discovered a race condition in the server\'s signal handling.
A remote attacker could exploit this to crash the server.
(CVE-2006-5051)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openssh-client-4.2p1-7ubuntu3.1 (Ubuntu 6.06)
- openssh-server-4.2p1-7ubuntu3.1 (Ubuntu 6.06)
- ssh-4.2p1-7ubuntu3.1 (Ubuntu 6.06)
- ssh-askpass-gnome-4.2p1-7ubuntu3.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-4924","CVE-2006-5051");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "openssh-client", pkgver: "4.2p1-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-client-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openssh-client-4.2p1-7ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openssh-server", pkgver: "4.2p1-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openssh-server-4.2p1-7ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ssh", pkgver: "4.2p1-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ssh-4.2p1-7ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ssh-askpass-gnome", pkgver: "4.2p1-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-askpass-gnome-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ssh-askpass-gnome-4.2p1-7ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
