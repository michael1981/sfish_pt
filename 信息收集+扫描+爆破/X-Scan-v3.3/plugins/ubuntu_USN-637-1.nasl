# This script was automatically generated from the 637-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(34048);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "637-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN637-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
- linux-doc-2.6.20 
- linux-doc-2.6.22 
- linux-doc-2.6.24 
- linux-headers-2.6.15-52 
- linux-headers-2.6.15-52-386 
- linux-headers-2.6.15-52-686 
- linux-headers-2.6.15-52-amd64-generic 
- linux-headers-2.6.15-52-amd64-k8 
- linux-headers-2.6.15-52-amd64-server 
- linux-headers-2.6.15-52-amd64-xeon 
- linux-headers-2.6.15-52-k7 
- linux-headers-2.6.15-52-powerpc 
- linux-headers-2.6.15-52-powerpc-smp 
- linux-headers-2.6.15-52-powe
[...]');
script_set_attribute(attribute:'description', value: 'It was discovered that there were multiple NULL-pointer function
dereferences in the Linux kernel terminal handling code. A local attacker
could exploit this to execute arbitrary code as root, or crash the system,
leading to a denial of service. (CVE-2008-2812)

The do_change_type routine did not correctly validation administrative
users. A local attacker could exploit this to block mount points or cause
private mounts to be shared, leading to denial of service or a possible
loss of privacy. (CVE-2008-2931)

Tobias Klein discovered that the OSS interface through ALSA did not
correctly validate the device number. A local attacker could exploit this
to access sensitive kernel memory, leading to a denial of service or a loss
of privacy. (CVE-2008-3272)

Zoltan Sogor discovered that new directory entries could be added to
already deleted directories. A local attacker could exploit this, filling
up available memory and disk space, leading to a denial of service.
(CVE-2008-3275)

In certain situations, the fix for
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-52.71 (Ubuntu 6.06)
- linux-doc-2.6.20-2.6.20-17.39 (Ubuntu 7.04)
- linux-doc-2.6.22-2.6.22-15.58 (Ubuntu 7.10)
- linux-doc-2.6.24-2.6.24-19.41 (Ubuntu 8.04)
- linux-headers-2.6.15-52-2.6.15-52.71 (Ubuntu 6.06)
- linux-headers-2.6.15-52-386-2.6.15-52.71 (Ubuntu 6.06)
- linux-headers-2.6.15-52-686-2.6.15-52.71 (Ubuntu 6.06)
- linux-headers-2.6.15-52-amd64-generic-2.6.15-52.71 (Ubuntu 6.06)
- linux-headers-2.6.15-52-amd64-k8-2.6.15-52.71 (Ubuntu 6.06)
- linux-headers-2
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-0598","CVE-2008-2812","CVE-2008-2931","CVE-2008-3272","CVE-2008-3275");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-52.71
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-doc-2.6.20", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-doc-2.6.20-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-doc-2.6.22", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-doc-2.6.22-2.6.22-15.58
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-doc-2.6.24", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-doc-2.6.24-2.6.24-19.41
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-386", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-386-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-686", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-686-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-generic", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-generic-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-k8", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-k8-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-server", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-server-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-xeon", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-xeon-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-k7", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-k7-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-powerpc", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-powerpc-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-powerpc-smp", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-powerpc-smp-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-powerpc64-smp", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-powerpc64-smp-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-server", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-server-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-server-bigiron", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-server-bigiron-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-sparc64", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-sparc64-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-sparc64-smp", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-sparc64-smp-2.6.15-52.71
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-386", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-386-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-generic", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-generic-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-lowlatency", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-lowlatency-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-powerpc", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-powerpc-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-powerpc-smp", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-powerpc-smp-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-powerpc64-smp", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-powerpc64-smp-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-server", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-server-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-server-bigiron", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-server-bigiron-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-sparc64", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-sparc64-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-sparc64-smp", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-sparc64-smp-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-386", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-386-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-cell", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-cell-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-generic", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-generic-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-powerpc", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-powerpc-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-powerpc-smp", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-powerpc-smp-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-powerpc64-smp", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-powerpc64-smp-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-rt", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-rt-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-server", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-server-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-sparc64", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-sparc64-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-sparc64-smp", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-sparc64-smp-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-ume", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-ume-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-virtual", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-virtual-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-xen", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-xen-2.6.22-15.58
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-386", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-386-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-generic", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-generic-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-openvz", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-openvz-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-rt", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-rt-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-server", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-server-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-virtual", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-virtual-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-xen", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-xen-2.6.24-19.41
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-386", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-386-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-686", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-686-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-generic", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-generic-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-k8", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-k8-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-server", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-server-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-xeon", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-xeon-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-k7", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-k7-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-powerpc", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-powerpc-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-powerpc-smp", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-powerpc-smp-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-powerpc64-smp", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-powerpc64-smp-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-server", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-server-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-server-bigiron", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-server-bigiron-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-sparc64", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-sparc64-2.6.15-52.71
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-sparc64-smp", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-sparc64-smp-2.6.15-52.71
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-386", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-386-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-generic", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-generic-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-lowlatency", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-lowlatency-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-powerpc", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-powerpc-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-powerpc-smp", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-powerpc-smp-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-powerpc64-smp", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-powerpc64-smp-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-server", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-server-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-server-bigiron", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-server-bigiron-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-sparc64", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-sparc64-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-sparc64-smp", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-sparc64-smp-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-386", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-386-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-cell", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-cell-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-generic", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-generic-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-powerpc", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-powerpc-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-powerpc-smp", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-powerpc-smp-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-powerpc64-smp", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-powerpc64-smp-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-rt", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-rt-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-server", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-server-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-sparc64", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-sparc64-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-sparc64-smp", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-sparc64-smp-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-ume", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-ume-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-virtual", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-virtual-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-xen", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-xen-2.6.22-15.58
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-386", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-386-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-generic", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-generic-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-openvz", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-openvz-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-rt", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-rt-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-server", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-server-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-virtual", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-virtual-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-xen", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-xen-2.6.24-19.41
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-386", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-386-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-generic", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-generic-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-lowlatency", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-lowlatency-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-powerpc", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-powerpc-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-powerpc-smp", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-powerpc-smp-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-powerpc64-smp", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-powerpc64-smp-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-server", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-server-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-server-bigiron", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-server-bigiron-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-sparc64", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-sparc64-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-sparc64-smp", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-sparc64-smp-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-386", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-386-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-generic", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-generic-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-server", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-server-2.6.22-15.58
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-virtual", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-virtual-2.6.22-15.58
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-19-386", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-19-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-19-386-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-19-generic", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-19-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-19-generic-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-19-server", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-19-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-19-server-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-19-virtual", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-19-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-19-virtual-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-kernel-devel", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-kernel-devel-2.6.24-19.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-libc-dev", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-libc-dev-2.6.24-19.41
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-52.71");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-52.71
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-source-2.6.20", pkgver: "2.6.20-17.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-source-2.6.20-2.6.20-17.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-source-2.6.22", pkgver: "2.6.22-15.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-source-2.6.22-2.6.22-15.58
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-source-2.6.24", pkgver: "2.6.24-19.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-source-2.6.24-2.6.24-19.41
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
