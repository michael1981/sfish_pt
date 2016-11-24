# This script was automatically generated from the 489-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28091);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "489-2");
script_summary(english:"redhat-cluster-suite vulnerability");
script_name(english:"USN489-2 : redhat-cluster-suite vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ccs 
- cman 
- fence 
- fence-gnbd 
- gfs-tools 
- gnbd-client 
- gnbd-server 
- gulm 
- libccs-dev 
- libcman-dev 
- libcman1 
- libdlm-dev 
- libdlm1 
- libgulm-dev 
- libgulm1 
- libiddev-dev 
- libmagma-dev 
- libmagma1 
- magma 
- magma-plugins 
- redhat-cluster-suite 
- redhat-cluster-suite-source 
- rgmanager 
');
script_set_attribute(attribute:'description', value: 'USN-489-1 fixed vulnerabilities in the Linux kernel.  This update
provides the corresponding fixes for the redhat cluster suite kernel
sources.

Original advisory details:

 A flaw was discovered in the cluster manager.  A remote attacker could
 connect to the DLM port and block further DLM operations.
 (CVE-2007-3380)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ccs-1.20060222-0ubuntu6.1 (Ubuntu 6.06)
- cman-1.20060222-0ubuntu6.1 (Ubuntu 6.06)
- fence-1.20060222-0ubuntu6.1 (Ubuntu 6.06)
- fence-gnbd-1.20060222-0ubuntu6.1 (Ubuntu 6.06)
- gfs-tools-1.20060222-0ubuntu6.1 (Ubuntu 6.06)
- gnbd-client-1.20060222-0ubuntu6.1 (Ubuntu 6.06)
- gnbd-server-1.20060222-0ubuntu6.1 (Ubuntu 6.06)
- gulm-1.20060222-0ubuntu6.1 (Ubuntu 6.06)
- libccs-dev-1.20060222-0ubuntu6.1 (Ubuntu 6.06)
- libcman-dev-1.20060222-0ubuntu6.1 (Ubuntu 6.06)
- libcman1-1.20060222-0ubuntu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-3380");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "ccs", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ccs-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ccs-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "cman", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cman-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to cman-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "fence", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fence-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to fence-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "fence-gnbd", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fence-gnbd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to fence-gnbd-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "gfs-tools", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gfs-tools-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gfs-tools-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "gnbd-client", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnbd-client-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gnbd-client-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "gnbd-server", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnbd-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gnbd-server-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "gulm", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gulm-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gulm-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libccs-dev", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libccs-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libccs-dev-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libcman-dev", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcman-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libcman-dev-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libcman1", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcman1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libcman1-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdlm-dev", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdlm-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdlm-dev-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdlm1", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdlm1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdlm1-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgulm-dev", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgulm-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgulm-dev-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgulm1", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgulm1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgulm1-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libiddev-dev", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libiddev-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libiddev-dev-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmagma-dev", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagma-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmagma-dev-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmagma1", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagma1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmagma1-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "magma", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package magma-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to magma-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "magma-plugins", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package magma-plugins-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to magma-plugins-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "redhat-cluster-suite", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package redhat-cluster-suite-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to redhat-cluster-suite-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "redhat-cluster-suite-source", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package redhat-cluster-suite-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to redhat-cluster-suite-source-1.20060222-0ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "rgmanager", pkgver: "1.20060222-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rgmanager-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to rgmanager-1.20060222-0ubuntu6.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
