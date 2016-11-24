# This script was automatically generated from the 612-5 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32359);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "612-5");
script_summary(english:"OpenSSH update");
script_name(english:"USN612-5 : OpenSSH update");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- openssh-client 
- openssh-server 
- ssh 
- ssh-askpass-gnome 
- ssh-krb5 
');
script_set_attribute(attribute:'description', value: 'Matt Zimmerman discovered that entries in ~/.ssh/authorized_keys
with options (such as "no-port-forwarding" or forced commands) were
ignored by the new ssh-vulnkey tool introduced in OpenSSH (see
USN-612-2). This could cause some compromised keys not to be
listed in ssh-vulnkey\'s output.

This update also adds more information to ssh-vulnkey\'s manual page.

Original advisory details:

 A weakness has been discovered in the random number generator used
 by OpenSSL on Debian and Ubuntu systems.  As a result of this
 weakness, certain encryption keys are much more common than they
 should be, such that an attacker could guess the key through a
 brute-force attack given minimal knowledge of the system.  This
 particularly affects the use of encryption keys in OpenSSH, OpenVPN
 and SSL certificates.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openssh-client-4.7p1-8ubuntu1.2 (Ubuntu 8.04)
- openssh-server-4.7p1-8ubuntu1.2 (Ubuntu 8.04)
- ssh-4.7p1-8ubuntu1.2 (Ubuntu 8.04)
- ssh-askpass-gnome-4.7p1-8ubuntu1.2 (Ubuntu 8.04)
- ssh-krb5-4.7p1-8ubuntu1.2 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "openssh-client", pkgver: "4.7p1-8ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-client-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openssh-client-4.7p1-8ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openssh-server", pkgver: "4.7p1-8ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openssh-server-4.7p1-8ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "ssh", pkgver: "4.7p1-8ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ssh-4.7p1-8ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "ssh-askpass-gnome", pkgver: "4.7p1-8ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-askpass-gnome-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ssh-askpass-gnome-4.7p1-8ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "ssh-krb5", pkgver: "4.7p1-8ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-krb5-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ssh-krb5-4.7p1-8ubuntu1.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
