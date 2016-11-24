# This script was automatically generated from the 670-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37886);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "670-1");
script_summary(english:"vm-builder vulnerability");
script_name(english:"USN670-1 : vm-builder vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- login 
- passwd 
- python-vm-builder 
- python-vm-builder-ec2 
- ubuntu-vm-builder 
');
script_set_attribute(attribute:'description', value: 'Mathias Gug discovered that vm-builder improperly set the root
password when creating virtual machines. An attacker could exploit
this to gain root privileges to the virtual machine by using a
predictable password.

This vulnerability only affects virtual machines created with
vm-builder under Ubuntu 8.10, and does not affect native Ubuntu
installations. An update was made to the shadow package to detect
vulnerable systems and disable password authentication for the
root account. Vulnerable virtual machines which an attacker has
access to should be considered compromised, and appropriate actions
taken to secure the machine.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- login-4.1.1-1ubuntu1.1 (Ubuntu 8.10)
- passwd-4.1.1-1ubuntu1.1 (Ubuntu 8.10)
- python-vm-builder-0.9-0ubuntu3.1 (Ubuntu 8.10)
- python-vm-builder-ec2-0.9-0ubuntu3.1 (Ubuntu 8.10)
- ubuntu-vm-builder-0.9-0ubuntu3.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "login", pkgver: "4.1.1-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package login-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to login-4.1.1-1ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "passwd", pkgver: "4.1.1-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package passwd-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to passwd-4.1.1-1ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "python-vm-builder", pkgver: "0.9-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-vm-builder-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-vm-builder-0.9-0ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "python-vm-builder-ec2", pkgver: "0.9-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-vm-builder-ec2-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-vm-builder-ec2-0.9-0ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ubuntu-vm-builder", pkgver: "0.9-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ubuntu-vm-builder-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ubuntu-vm-builder-0.9-0ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
