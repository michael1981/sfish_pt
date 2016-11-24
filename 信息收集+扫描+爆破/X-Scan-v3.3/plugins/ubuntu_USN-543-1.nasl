# This script was automatically generated from the 543-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28250);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "543-1");
script_summary(english:"VMWare vulnerabilities");
script_name(english:"USN543-1 : VMWare vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avm-fritz-firmware-2.6.17-12 
- avm-fritz-firmware-2.6.20-16 
- avm-fritz-kernel-source 
- fglrx-control 
- fglrx-kernel-source 
- linux-restricted-modules-2.6.17-12-386 
- linux-restricted-modules-2.6.17-12-generic 
- linux-restricted-modules-2.6.17-12-powerpc 
- linux-restricted-modules-2.6.17-12-powerpc-smp 
- linux-restricted-modules-2.6.17-12-powerpc64-smp 
- linux-restricted-modules-2.6.17-12-sparc64 
- linux-restricted-modules-2.6.17-12-sparc64-
[...]');
script_set_attribute(attribute:'description', value: 'Neel Mehta and Ryan Smith discovered that the VMWare Player DHCP server
did not correctly handle certain packet structures.  Remote attackers
could send specially crafted packets and gain root privileges.
(CVE-2007-0061, CVE-2007-0062, CVE-2007-0063)

Rafal Wojtczvk discovered multiple memory corruption issues in VMWare
Player.  Attackers with administrative privileges in a guest operating
system could cause a denial of service or possibly execute arbitrary
code on the host operating system.  (CVE-2007-4496, CVE-2007-4497)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avm-fritz-firmware-2.6.17-12-3.11+2.6.17.9-12.4 (Ubuntu 6.10)
- avm-fritz-firmware-2.6.20-16-3.11+2.6.20.6-16.30 (Ubuntu 7.04)
- avm-fritz-kernel-source-3.11+2.6.20.6-16.30 (Ubuntu 7.04)
- fglrx-control-8.34.8+2.6.20.6-16.30 (Ubuntu 7.04)
- fglrx-kernel-source-8.34.8+2.6.20.6-16.30 (Ubuntu 7.04)
- linux-restricted-modules-2.6.17-12-386-2.6.17.9-12.4 (Ubuntu 6.10)
- linux-restricted-modules-2.6.17-12-generic-2.6.17.9-12.4 (Ubuntu 6.10)
- linux-restricted-modules-2.6.17-12-powerpc-2.6.17.9-12
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-0061","CVE-2007-0062","CVE-2007-0063","CVE-2007-4496","CVE-2007-4497");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "avm-fritz-firmware-2.6.17-12", pkgver: "3.11+2.6.17.9-12.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.17-12-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to avm-fritz-firmware-2.6.17-12-3.11+2.6.17.9-12.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "avm-fritz-firmware-2.6.20-16", pkgver: "3.11+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to avm-fritz-firmware-2.6.20-16-3.11+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "avm-fritz-kernel-source", pkgver: "3.11+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-kernel-source-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to avm-fritz-kernel-source-3.11+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "fglrx-control", pkgver: "8.34.8+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-control-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to fglrx-control-8.34.8+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "fglrx-kernel-source", pkgver: "8.34.8+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-kernel-source-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to fglrx-kernel-source-8.34.8+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-12-386", pkgver: "2.6.17.9-12.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-12-386-2.6.17.9-12.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-12-generic", pkgver: "2.6.17.9-12.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-12-generic-2.6.17.9-12.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-12-powerpc", pkgver: "2.6.17.9-12.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-12-powerpc-2.6.17.9-12.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-12-powerpc-smp", pkgver: "2.6.17.9-12.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-12-powerpc-smp-2.6.17.9-12.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.9-12.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-12-powerpc64-smp-2.6.17.9-12.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-12-sparc64", pkgver: "2.6.17.9-12.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-12-sparc64-2.6.17.9-12.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-12-sparc64-smp", pkgver: "2.6.17.9-12.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-12-sparc64-smp-2.6.17.9-12.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-386", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-386-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-generic", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-generic-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-lowlatency", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-lowlatency-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-powerpc", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-powerpc-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-powerpc-smp", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-powerpc-smp-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-powerpc64-smp", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-powerpc64-smp-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-sparc64", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-sparc64-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-sparc64-smp", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-sparc64-smp-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-common", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-common-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx", pkgver: "1.0.9631+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-1.0.9631+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx-dev", pkgver: "1.0.9631+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-dev-1.0.9631+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx-legacy", pkgver: "1.0.7184+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-legacy-1.0.7184+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx-legacy-dev", pkgver: "1.0.7184+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-legacy-dev-1.0.7184+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx-new", pkgver: "1.0.9755+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-new-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-new-1.0.9755+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx-new-dev", pkgver: "1.0.9755+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-new-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-new-dev-1.0.9755+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-kernel-source", pkgver: "1.0.9631+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-kernel-source-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-kernel-source-1.0.9631+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-legacy-kernel-source", pkgver: "1.0.7184+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-legacy-kernel-source-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-legacy-kernel-source-1.0.7184+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-new-kernel-source", pkgver: "1.0.9755+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-new-kernel-source-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-new-kernel-source-1.0.9755+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "6.06", pkgname: "vmware-player-kernel-modules", pkgver: "2.6.15.11-13");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to vmware-player-kernel-modules-2.6.15.11-13
');
}
found = ubuntu_check(osver: "6.06", pkgname: "vmware-player-kernel-modules-2.6.15-29", pkgver: "2.6.15.11-13");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-2.6.15-29-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to vmware-player-kernel-modules-2.6.15-29-2.6.15.11-13
');
}
found = ubuntu_check(osver: "6.10", pkgname: "vmware-player-kernel-modules-2.6.17-12", pkgver: "2.6.17.9-12.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-2.6.17-12-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to vmware-player-kernel-modules-2.6.17-12-2.6.17.9-12.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vmware-player-kernel-modules-2.6.20-16", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vmware-player-kernel-modules-2.6.20-16-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "6.06", pkgname: "vmware-player-kernel-source", pkgver: "2.6.15.11-13");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to vmware-player-kernel-source-2.6.15.11-13
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vmware-server-kernel-modules-2.6.20-16", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-server-kernel-modules-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vmware-server-kernel-modules-2.6.20-16-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vmware-tools-kernel-modules-2.6.20-16", pkgver: "2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-tools-kernel-modules-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vmware-tools-kernel-modules-2.6.20-16-2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xorg-driver-fglrx", pkgver: "7.1.0-8.34.8+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xorg-driver-fglrx-7.1.0-8.34.8+2.6.20.6-16.30
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xorg-driver-fglrx-dev", pkgver: "7.1.0-8.34.8+2.6.20.6-16.30");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xorg-driver-fglrx-dev-7.1.0-8.34.8+2.6.20.6-16.30
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
