# This script was automatically generated from the 476-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28077);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "476-1");
script_summary(english:"redhat-cluster-suite vulnerability");
script_name(english:"USN476-1 : redhat-cluster-suite vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- cman 
- gfs-tools 
- gfs2-tools 
- gnbd-client 
- gnbd-server 
- libccs-dev 
- libcman-dev 
- libcman2 
- libdlm-dev 
- libdlm2 
- redhat-cluster-suite 
- rgmanager 
');
script_set_attribute(attribute:'description', value: 'Fabio Massimo Di Nitto discovered that cman did not correctly validate
the size of client messages.  A local user could send a specially crafted
message and execute arbitrary code with cluster manager privileges or
crash the manager, leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- cman-2.20070315-0ubuntu2.1 (Ubuntu 7.04)
- gfs-tools-2.20070315-0ubuntu2.1 (Ubuntu 7.04)
- gfs2-tools-2.20070315-0ubuntu2.1 (Ubuntu 7.04)
- gnbd-client-2.20070315-0ubuntu2.1 (Ubuntu 7.04)
- gnbd-server-2.20070315-0ubuntu2.1 (Ubuntu 7.04)
- libccs-dev-2.20070315-0ubuntu2.1 (Ubuntu 7.04)
- libcman-dev-2.20070315-0ubuntu2.1 (Ubuntu 7.04)
- libcman2-2.20070315-0ubuntu2.1 (Ubuntu 7.04)
- libdlm-dev-2.20070315-0ubuntu2.1 (Ubuntu 7.04)
- libdlm2-2.20070315-0ubuntu2.1 (Ubuntu 7.04)
- redhat-cluster
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "cman", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cman-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to cman-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "gfs-tools", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gfs-tools-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to gfs-tools-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "gfs2-tools", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gfs2-tools-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to gfs2-tools-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "gnbd-client", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnbd-client-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to gnbd-client-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "gnbd-server", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnbd-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to gnbd-server-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libccs-dev", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libccs-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libccs-dev-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libcman-dev", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcman-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libcman-dev-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libcman2", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcman2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libcman2-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libdlm-dev", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdlm-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libdlm-dev-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libdlm2", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdlm2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libdlm2-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "redhat-cluster-suite", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package redhat-cluster-suite-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to redhat-cluster-suite-2.20070315-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "rgmanager", pkgver: "2.20070315-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rgmanager-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to rgmanager-2.20070315-0ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
