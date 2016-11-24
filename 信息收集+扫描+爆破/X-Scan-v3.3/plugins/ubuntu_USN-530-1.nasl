# This script was automatically generated from the 530-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28135);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "530-1");
script_summary(english:"hplip vulnerability");
script_name(english:"USN530-1 : hplip vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- hpijs 
- hpijs-ppds 
- hplip 
- hplip-data 
- hplip-dbg 
- hplip-doc 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the hpssd tool of hplip did not correctly handle
shell meta-characters.  A local attacker could exploit this to execute
arbitrary commands as the hplip user.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- hpijs-2.7.2+1.7.3-0ubuntu1.1 (Ubuntu 7.04)
- hpijs-ppds-2.7.2+1.7.3-0ubuntu1.1 (Ubuntu 7.04)
- hplip-1.7.3-0ubuntu1.1 (Ubuntu 7.04)
- hplip-data-1.7.3-0ubuntu1.1 (Ubuntu 7.04)
- hplip-dbg-1.7.3-0ubuntu1.1 (Ubuntu 7.04)
- hplip-doc-1.7.3-0ubuntu1.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-5208");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "hpijs", pkgver: "2.7.2+1.7.3-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hpijs-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to hpijs-2.7.2+1.7.3-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "hpijs-ppds", pkgver: "2.7.2+1.7.3-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hpijs-ppds-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to hpijs-ppds-2.7.2+1.7.3-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "hplip", pkgver: "1.7.3-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to hplip-1.7.3-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "hplip-data", pkgver: "1.7.3-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-data-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to hplip-data-1.7.3-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "hplip-dbg", pkgver: "1.7.3-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-dbg-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to hplip-dbg-1.7.3-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "hplip-doc", pkgver: "1.7.3-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-doc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to hplip-doc-1.7.3-0ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
