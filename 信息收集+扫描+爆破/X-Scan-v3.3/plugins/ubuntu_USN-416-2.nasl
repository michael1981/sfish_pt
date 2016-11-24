# This script was automatically generated from the 416-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28006);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "416-2");
script_summary(english:"nvidia-glx-config regression");
script_name(english:"USN416-2 : nvidia-glx-config regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avm-fritz-firmware-2.6.17-11 
- avm-fritz-kernel-source 
- fglrx-control 
- fglrx-kernel-source 
- linux-restricted-modules-2.6.17-11-386 
- linux-restricted-modules-2.6.17-11-generic 
- linux-restricted-modules-2.6.17-11-powerpc 
- linux-restricted-modules-2.6.17-11-powerpc-smp 
- linux-restricted-modules-2.6.17-11-powerpc64-smp 
- linux-restricted-modules-2.6.17-11-sparc64 
- linux-restricted-modules-2.6.17-11-sparc64-smp 
- linux-restricted-modules-
[...]');
script_set_attribute(attribute:'description', value: 'USN-416-1 fixed various vulnerabilities in the Linux kernel.
Unfortunately that update caused the \'nvidia-glx-config\' script to not
work any more. The new version fixes the problem.

We apologize for the inconvenience.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avm-fritz-firmware-2.6.17-11-3.11+2.6.17.7-11.2 (Ubuntu 6.10)
- avm-fritz-kernel-source-3.11+2.6.17.7-11.2 (Ubuntu 6.10)
- fglrx-control-8.28.8+2.6.17.7-11.2 (Ubuntu 6.10)
- fglrx-kernel-source-8.28.8+2.6.17.7-11.2 (Ubuntu 6.10)
- linux-restricted-modules-2.6.17-11-386-2.6.17.7-11.2 (Ubuntu 6.10)
- linux-restricted-modules-2.6.17-11-generic-2.6.17.7-11.2 (Ubuntu 6.10)
- linux-restricted-modules-2.6.17-11-powerpc-2.6.17.7-11.2 (Ubuntu 6.10)
- linux-restricted-modules-2.6.17-11-powerpc-smp-2.
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "avm-fritz-firmware-2.6.17-11", pkgver: "3.11+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.17-11-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to avm-fritz-firmware-2.6.17-11-3.11+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "avm-fritz-kernel-source", pkgver: "3.11+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-kernel-source-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to avm-fritz-kernel-source-3.11+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "fglrx-control", pkgver: "8.28.8+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-control-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to fglrx-control-8.28.8+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "fglrx-kernel-source", pkgver: "8.28.8+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-kernel-source-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to fglrx-kernel-source-8.28.8+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-386", pkgver: "2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-386-2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-generic", pkgver: "2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-generic-2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-powerpc", pkgver: "2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-powerpc-2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-powerpc-smp", pkgver: "2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-powerpc-smp-2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-powerpc64-smp", pkgver: "2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-powerpc64-smp-2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-sparc64", pkgver: "2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-sparc64-2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-sparc64-smp", pkgver: "2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-sparc64-smp-2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-common", pkgver: "2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-common-2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-glx", pkgver: "1.0.8776+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-glx-1.0.8776+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-glx-dev", pkgver: "1.0.8776+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-glx-dev-1.0.8776+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-glx-legacy", pkgver: "1.0.7184+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-glx-legacy-1.0.7184+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-glx-legacy-dev", pkgver: "1.0.7184+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-glx-legacy-dev-1.0.7184+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-kernel-source", pkgver: "1.0.8776+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-kernel-source-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-kernel-source-1.0.8776+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-legacy-kernel-source", pkgver: "1.0.7184+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-legacy-kernel-source-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-legacy-kernel-source-1.0.7184+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "vmware-player-kernel-modules-2.6.17-11", pkgver: "2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-2.6.17-11-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to vmware-player-kernel-modules-2.6.17-11-2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xorg-driver-fglrx", pkgver: "7.1.0-8.28.8+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xorg-driver-fglrx-7.1.0-8.28.8+2.6.17.7-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xorg-driver-fglrx-dev", pkgver: "7.1.0-8.28.8+2.6.17.7-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xorg-driver-fglrx-dev-7.1.0-8.28.8+2.6.17.7-11.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
