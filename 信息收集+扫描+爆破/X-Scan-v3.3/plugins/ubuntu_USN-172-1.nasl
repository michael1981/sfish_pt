# This script was automatically generated from the 172-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20579);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "172-1");
script_summary(english:"lm-sensors vulnerabilities");
script_name(english:"USN172-1 : lm-sensors vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libsensors-dev 
- libsensors3 
- lm-sensors 
- sensord 
');
script_set_attribute(attribute:'description', value: 'Javier Fernández-Sanguino Peña noticed that the pwmconfig script
created temporary files in an insecure manner. This could allow
a symlink attack to create or overwrite arbitrary files with full
root privileges since pwmconfig is usually executed by root.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libsensors-dev-2.8.8-7ubuntu2.1 (Ubuntu 5.04)
- libsensors3-2.8.8-7ubuntu2.1 (Ubuntu 5.04)
- lm-sensors-2.8.8-7ubuntu2.1 (Ubuntu 5.04)
- sensord-2.8.8-7ubuntu2.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "libsensors-dev", pkgver: "2.8.8-7ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsensors-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsensors-dev-2.8.8-7ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libsensors3", pkgver: "2.8.8-7ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsensors3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsensors3-2.8.8-7ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "lm-sensors", pkgver: "2.8.8-7ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lm-sensors-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to lm-sensors-2.8.8-7ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "sensord", pkgver: "2.8.8-7ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sensord-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to sensord-2.8.8-7ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
