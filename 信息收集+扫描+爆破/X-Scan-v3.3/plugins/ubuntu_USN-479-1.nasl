# This script was automatically generated from the 479-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28080);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "479-1");
script_summary(english:"MadWifi vulnerabilities");
script_name(english:"USN479-1 : MadWifi vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avm-fritz-firmware-2.6.15-28 
- avm-fritz-firmware-2.6.17-11 
- avm-fritz-firmware-2.6.20-16 
- avm-fritz-kernel-source 
- fglrx-control 
- fglrx-kernel-source 
- linux-restricted-modules-2.6.15-28-386 
- linux-restricted-modules-2.6.15-28-686 
- linux-restricted-modules-2.6.15-28-amd64-generic 
- linux-restricted-modules-2.6.15-28-amd64-k8 
- linux-restricted-modules-2.6.15-28-amd64-xeon 
- linux-restricted-modules-2.6.15-28-k7 
- linux-restricted-mod
[...]');
script_set_attribute(attribute:'description', value: 'Multiple flaws in the MadWifi driver were discovered that could lead
to a system crash.  A physically near-by attacker could generate
specially crafted wireless network traffic and cause a denial of
service. (CVE-2006-7177, CVE-2006-7178, CVE-2006-7179, CVE-2007-2829,
CVE-2007-2830)

A flaw was discovered in the MadWifi driver that would allow unencrypted
network traffic to be sent prior to finishing WPA authentication.
A physically near-by attacker could capture this, leading to a loss of
privacy, denial of service, or network spoofing. (CVE-2006-7180)

A flaw was discovered in the MadWifi driver\'s ioctl handling.  A local
attacker could read kernel memory, or crash the system, leading to a
denial of service. (CVE-2007-2831)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avm-fritz-firmware-2.6.15-28-3.11+2.6.15.12-28.2 (Ubuntu 6.06)
- avm-fritz-firmware-2.6.17-11-3.11+2.6.17.8-11.2 (Ubuntu 6.10)
- avm-fritz-firmware-2.6.20-16-3.11+2.6.20.5-16.29 (Ubuntu 7.04)
- avm-fritz-kernel-source-3.11+2.6.20.5-16.29 (Ubuntu 7.04)
- fglrx-control-8.34.8+2.6.20.5-16.29 (Ubuntu 7.04)
- fglrx-kernel-source-8.34.8+2.6.20.5-16.29 (Ubuntu 7.04)
- linux-restricted-modules-2.6.15-28-386-2.6.15.12-28.2 (Ubuntu 6.06)
- linux-restricted-modules-2.6.15-28-686-2.6.15.12-28.2 (Ubuntu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-7177","CVE-2006-7178","CVE-2006-7179","CVE-2006-7180","CVE-2007-2829","CVE-2007-2830","CVE-2007-2831");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "avm-fritz-firmware-2.6.15-28", pkgver: "3.11+2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.15-28-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to avm-fritz-firmware-2.6.15-28-3.11+2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "avm-fritz-firmware-2.6.17-11", pkgver: "3.11+2.6.17.8-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.17-11-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to avm-fritz-firmware-2.6.17-11-3.11+2.6.17.8-11.2
');
}
found = ubuntu_check(osver: "7.04", pkgname: "avm-fritz-firmware-2.6.20-16", pkgver: "3.11+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to avm-fritz-firmware-2.6.20-16-3.11+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "avm-fritz-kernel-source", pkgver: "3.11+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-kernel-source-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to avm-fritz-kernel-source-3.11+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "fglrx-control", pkgver: "8.34.8+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-control-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to fglrx-control-8.34.8+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "fglrx-kernel-source", pkgver: "8.34.8+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-kernel-source-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to fglrx-kernel-source-8.34.8+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-28-386", pkgver: "2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-28-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-28-386-2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-28-686", pkgver: "2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-28-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-28-686-2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-28-amd64-generic", pkgver: "2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-28-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-28-amd64-generic-2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-28-amd64-k8", pkgver: "2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-28-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-28-amd64-k8-2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-28-amd64-xeon", pkgver: "2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-28-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-28-amd64-xeon-2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-28-k7", pkgver: "2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-28-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-28-k7-2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-28-powerpc", pkgver: "2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-28-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-28-powerpc-2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-28-powerpc-smp", pkgver: "2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-28-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-28-powerpc-smp-2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-28-sparc64", pkgver: "2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-28-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-28-sparc64-2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-28-sparc64-smp", pkgver: "2.6.15.12-28.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-28-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-28-sparc64-smp-2.6.15.12-28.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-386", pkgver: "2.6.17.8-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-386-2.6.17.8-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-generic", pkgver: "2.6.17.8-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-generic-2.6.17.8-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-powerpc", pkgver: "2.6.17.8-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-powerpc-2.6.17.8-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-powerpc-smp", pkgver: "2.6.17.8-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-powerpc-smp-2.6.17.8-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-powerpc64-smp", pkgver: "2.6.17.8-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-powerpc64-smp-2.6.17.8-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-sparc64", pkgver: "2.6.17.8-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-sparc64-2.6.17.8-11.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-11-sparc64-smp", pkgver: "2.6.17.8-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-11-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-11-sparc64-smp-2.6.17.8-11.2
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-386", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-386-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-generic", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-generic-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-lowlatency", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-lowlatency-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-powerpc", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-powerpc-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-powerpc-smp", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-powerpc-smp-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-powerpc64-smp", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-powerpc64-smp-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-sparc64", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-sparc64-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-16-sparc64-smp", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-16-sparc64-smp-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-common", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-common-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx", pkgver: "1.0.9631+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-1.0.9631+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx-dev", pkgver: "1.0.9631+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-dev-1.0.9631+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx-legacy", pkgver: "1.0.7184+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-legacy-1.0.7184+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx-legacy-dev", pkgver: "1.0.7184+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-legacy-dev-1.0.7184+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx-new", pkgver: "1.0.9755+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-new-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-new-1.0.9755+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-glx-new-dev", pkgver: "1.0.9755+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-new-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-glx-new-dev-1.0.9755+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-kernel-source", pkgver: "1.0.9631+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-kernel-source-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-kernel-source-1.0.9631+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-legacy-kernel-source", pkgver: "1.0.7184+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-legacy-kernel-source-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-legacy-kernel-source-1.0.7184+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "nvidia-new-kernel-source", pkgver: "1.0.9755+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-new-kernel-source-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to nvidia-new-kernel-source-1.0.9755+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "6.10", pkgname: "vmware-player-kernel-modules-2.6.17-11", pkgver: "2.6.17.8-11.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-2.6.17-11-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to vmware-player-kernel-modules-2.6.17-11-2.6.17.8-11.2
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vmware-player-kernel-modules-2.6.20-16", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vmware-player-kernel-modules-2.6.20-16-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vmware-server-kernel-modules-2.6.20-16", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-server-kernel-modules-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vmware-server-kernel-modules-2.6.20-16-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vmware-tools-kernel-modules-2.6.20-16", pkgver: "2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-tools-kernel-modules-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vmware-tools-kernel-modules-2.6.20-16-2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xorg-driver-fglrx", pkgver: "7.1.0-8.34.8+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xorg-driver-fglrx-7.1.0-8.34.8+2.6.20.5-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xorg-driver-fglrx-dev", pkgver: "7.1.0-8.34.8+2.6.20.5-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xorg-driver-fglrx-dev-7.1.0-8.34.8+2.6.20.5-16.29
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
