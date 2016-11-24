# This script was automatically generated from the 377-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27959);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "377-1");
script_summary(english:"NVIDIA vulnerability");
script_name(english:"USN377-1 : NVIDIA vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avm-fritz-firmware-2.6.15-27 
- avm-fritz-firmware-2.6.17-10 
- avm-fritz-kernel-source 
- fglrx-control 
- fglrx-kernel-source 
- linux-restricted-modules-2.6.15-27-386 
- linux-restricted-modules-2.6.15-27-686 
- linux-restricted-modules-2.6.15-27-amd64-generic 
- linux-restricted-modules-2.6.15-27-amd64-k8 
- linux-restricted-modules-2.6.15-27-amd64-xeon 
- linux-restricted-modules-2.6.15-27-k7 
- linux-restricted-modules-2.6.15-27-powerpc 
- linux-
[...]');
script_set_attribute(attribute:'description', value: 'Derek Abdine discovered that the NVIDIA Xorg driver did not correctly 
verify the size of buffers used to render text glyphs.  When displaying 
very long strings of text, the Xorg server would crash.  If a user were 
tricked into viewing a specially crafted series of glyphs, this flaw 
could be exploited to run arbitrary code with root privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avm-fritz-firmware-2.6.15-27-3.11+2.6.15.12-1 (Ubuntu 6.06)
- avm-fritz-firmware-2.6.17-10-3.11+2.6.17.6-1 (Ubuntu 6.10)
- avm-fritz-kernel-source-3.11+2.6.17.6-1 (Ubuntu 6.10)
- fglrx-control-8.28.8+2.6.17.6-1 (Ubuntu 6.10)
- fglrx-kernel-source-8.28.8+2.6.17.6-1 (Ubuntu 6.10)
- linux-restricted-modules-2.6.15-27-386-2.6.15.12-1 (Ubuntu 6.06)
- linux-restricted-modules-2.6.15-27-686-2.6.15.12-1 (Ubuntu 6.06)
- linux-restricted-modules-2.6.15-27-amd64-generic-2.6.15.12-1 (Ubuntu 6.06)
- lin
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-5379");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "avm-fritz-firmware-2.6.15-27", pkgver: "3.11+2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.15-27-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to avm-fritz-firmware-2.6.15-27-3.11+2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "avm-fritz-firmware-2.6.17-10", pkgver: "3.11+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.17-10-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to avm-fritz-firmware-2.6.17-10-3.11+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "avm-fritz-kernel-source", pkgver: "3.11+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-kernel-source-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to avm-fritz-kernel-source-3.11+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "fglrx-control", pkgver: "8.28.8+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-control-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to fglrx-control-8.28.8+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "fglrx-kernel-source", pkgver: "8.28.8+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-kernel-source-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to fglrx-kernel-source-8.28.8+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-386", pkgver: "2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-386-2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-686", pkgver: "2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-686-2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-amd64-generic", pkgver: "2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-amd64-generic-2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-amd64-k8", pkgver: "2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-amd64-k8-2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-amd64-xeon", pkgver: "2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-amd64-xeon-2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-k7", pkgver: "2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-k7-2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-powerpc", pkgver: "2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-powerpc-2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-powerpc-smp", pkgver: "2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-powerpc-smp-2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-sparc64", pkgver: "2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-sparc64-2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-sparc64-smp", pkgver: "2.6.15.12-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-sparc64-smp-2.6.15.12-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-10-386", pkgver: "2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-10-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-10-386-2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-10-generic", pkgver: "2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-10-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-10-generic-2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-10-powerpc", pkgver: "2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-10-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-10-powerpc-2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-10-powerpc-smp", pkgver: "2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-10-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-10-powerpc-smp-2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-10-powerpc64-smp", pkgver: "2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-10-powerpc64-smp-2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-10-sparc64", pkgver: "2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-10-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-10-sparc64-2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-2.6.17-10-sparc64-smp", pkgver: "2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.17-10-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-2.6.17-10-sparc64-smp-2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-restricted-modules-common", pkgver: "2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-restricted-modules-common-2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-glx", pkgver: "1.0.8776+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-glx-1.0.8776+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-glx-dev", pkgver: "1.0.8776+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-glx-dev-1.0.8776+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-glx-legacy", pkgver: "1.0.7184+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-glx-legacy-1.0.7184+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-glx-legacy-dev", pkgver: "1.0.7184+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-glx-legacy-dev-1.0.7184+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-kernel-source", pkgver: "1.0.8776+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-kernel-source-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-kernel-source-1.0.8776+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nvidia-legacy-kernel-source", pkgver: "1.0.7184+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-legacy-kernel-source-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nvidia-legacy-kernel-source-1.0.7184+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "vmware-player-kernel-modules-2.6.17-10", pkgver: "2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-2.6.17-10-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to vmware-player-kernel-modules-2.6.17-10-2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xorg-driver-fglrx", pkgver: "7.1.0-8.28.8+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xorg-driver-fglrx-7.1.0-8.28.8+2.6.17.6-1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xorg-driver-fglrx-dev", pkgver: "7.1.0-8.28.8+2.6.17.6-1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xorg-driver-fglrx-dev-7.1.0-8.28.8+2.6.17.6-1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
