# This script was automatically generated from the 255-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21063);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "255-1");
script_summary(english:"openssh vulnerability");
script_name(english:"USN255-1 : openssh vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- openssh-client 
- openssh-server 
- ssh 
- ssh-askpass-gnome 
');
script_set_attribute(attribute:'description', value: 'Tomas Mraz discovered a shell code injection flaw in scp. When doing
local-to-local or remote-to-remote copying, scp expanded shell escape
characters. By tricking an user into using scp on a specially crafted
file name (which could also be caught by using an innocuous wild card
like \'*\'), an attacker could exploit this to execute arbitrary shell
commands with the privilege of that user.

Please be aware that scp is not designed to operate securely on
untrusted file names, since it needs to stay compatible with rcp.
Please use sftp for automated systems and potentially untrusted file
names.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openssh-client-4.1p1-7ubuntu4.1 (Ubuntu 5.10)
- openssh-server-4.1p1-7ubuntu4.1 (Ubuntu 5.10)
- ssh-4.1p1-7ubuntu4.1 (Ubuntu 5.10)
- ssh-askpass-gnome-4.1p1-7ubuntu4.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-0225");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "openssh-client", pkgver: "4.1p1-7ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-client-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openssh-client-4.1p1-7ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openssh-server", pkgver: "4.1p1-7ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-server-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openssh-server-4.1p1-7ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "ssh", pkgver: "4.1p1-7ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ssh-4.1p1-7ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "ssh-askpass-gnome", pkgver: "4.1p1-7ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-askpass-gnome-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to ssh-askpass-gnome-4.1p1-7ubuntu4.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
