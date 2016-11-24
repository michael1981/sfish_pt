# This script was automatically generated from the 758-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36530);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "758-1");
script_summary(english:"udev vulnerabilities");
script_name(english:"USN758-1 : udev vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libvolume-id-dev 
- libvolume-id0 
- udev 
- volumeid 
');
script_set_attribute(attribute:'description', value: 'Sebastian Krahmer discovered that udev did not correctly validate netlink
message senders.  A local attacker could send specially crafted messages
to udev in order to gain root privileges. (CVE-2009-1185)

Sebastian Krahmer discovered a buffer overflow in the path encoding routines
in udev.  A local attacker could exploit this to crash udev, leading to a
denial of service. (CVE-2009-1186)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libvolume-id-dev-124-9ubuntu0.2 (Ubuntu 8.10)
- libvolume-id0-124-9ubuntu0.2 (Ubuntu 8.10)
- udev-124-9ubuntu0.2 (Ubuntu 8.10)
- volumeid-113-0ubuntu17.2 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1185","CVE-2009-1186");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libvolume-id-dev", pkgver: "124-9ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvolume-id-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libvolume-id-dev-124-9ubuntu0.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libvolume-id0", pkgver: "124-9ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvolume-id0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libvolume-id0-124-9ubuntu0.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "udev", pkgver: "124-9ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package udev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to udev-124-9ubuntu0.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "volumeid", pkgver: "113-0ubuntu17.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package volumeid-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to volumeid-113-0ubuntu17.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
