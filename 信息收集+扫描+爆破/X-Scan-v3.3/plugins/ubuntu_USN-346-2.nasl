# This script was automatically generated from the 346-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27926);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "346-2");
script_summary(english:"Fixed linux-restricted-modules-2.6.15");
script_name(english:"USN346-2 : Fixed linux-restricted-modules-2.6.15");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avm-fritz-firmware-2.6.15-26 
- avm-fritz-kernel-source 
- fglrx-control 
- fglrx-kernel-source 
- linux-restricted-modules-2.6.15-26-386 
- linux-restricted-modules-2.6.15-26-686 
- linux-restricted-modules-2.6.15-26-amd64-generic 
- linux-restricted-modules-2.6.15-26-amd64-k8 
- linux-restricted-modules-2.6.15-26-amd64-xeon 
- linux-restricted-modules-2.6.15-26-k7 
- linux-restricted-modules-2.6.15-26-powerpc 
- linux-restricted-modules-2.6.15-26-pow
[...]');
script_set_attribute(attribute:'description', value: 'USN-346-1 provided an updated Linux kernel to fix several security
vulnerabilities. Unfortunately the update broke the binary \'nvidia\'
driver from linux-restricted-modules. This update corrects this
problem. We apologize for the inconvenience.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avm-fritz-firmware-2.6.15-26-3.11+2.6.15.11-4 (Ubuntu 6.06)
- avm-fritz-kernel-source-3.11+2.6.15.11-4 (Ubuntu 6.06)
- fglrx-control-8.25.18+2.6.15.11-4 (Ubuntu 6.06)
- fglrx-kernel-source-8.25.18+2.6.15.11-4 (Ubuntu 6.06)
- linux-restricted-modules-2.6.15-26-386-2.6.15.11-4 (Ubuntu 6.06)
- linux-restricted-modules-2.6.15-26-686-2.6.15.11-4 (Ubuntu 6.06)
- linux-restricted-modules-2.6.15-26-amd64-generic-2.6.15.11-4 (Ubuntu 6.06)
- linux-restricted-modules-2.6.15-26-amd64-k8-2.6.15.11-4 (Ub
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "avm-fritz-firmware-2.6.15-26", pkgver: "3.11+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.15-26-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to avm-fritz-firmware-2.6.15-26-3.11+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "avm-fritz-kernel-source", pkgver: "3.11+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-kernel-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to avm-fritz-kernel-source-3.11+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "fglrx-control", pkgver: "8.25.18+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-control-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to fglrx-control-8.25.18+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "fglrx-kernel-source", pkgver: "8.25.18+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-kernel-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to fglrx-kernel-source-8.25.18+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-26-386", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-26-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-26-386-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-26-686", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-26-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-26-686-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-26-amd64-generic", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-26-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-26-amd64-generic-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-26-amd64-k8", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-26-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-26-amd64-k8-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-26-amd64-xeon", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-26-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-26-amd64-xeon-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-26-k7", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-26-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-26-k7-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-26-powerpc", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-26-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-26-powerpc-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-26-powerpc-smp", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-26-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-26-powerpc-smp-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-26-sparc64", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-26-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-26-sparc64-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-26-sparc64-smp", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-26-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-26-sparc64-smp-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-common", pkgver: "2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-common-2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-glx", pkgver: "1.0.8762+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-glx-1.0.8762+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-glx-dev", pkgver: "1.0.8762+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-glx-dev-1.0.8762+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-glx-legacy", pkgver: "1.0.7174+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-glx-legacy-1.0.7174+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-glx-legacy-dev", pkgver: "1.0.7174+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-glx-legacy-dev-1.0.7174+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-kernel-source", pkgver: "1.0.8762+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-kernel-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-kernel-source-1.0.8762+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-legacy-kernel-source", pkgver: "1.0.7174+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-legacy-kernel-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-legacy-kernel-source-1.0.7174+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "xorg-driver-fglrx", pkgver: "7.0.0-8.25.18+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xorg-driver-fglrx-7.0.0-8.25.18+2.6.15.11-4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "xorg-driver-fglrx-dev", pkgver: "7.0.0-8.25.18+2.6.15.11-4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xorg-driver-fglrx-dev-7.0.0-8.25.18+2.6.15.11-4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
