# This script was automatically generated from the 664-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37631);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "664-1");
script_summary(english:"tk8.0, tk8.3, tk8.4 vulnerability");
script_name(english:"USN664-1 : tk8.0, tk8.3, tk8.4 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- tk8.0 
- tk8.0-dev 
- tk8.0-doc 
- tk8.3 
- tk8.3-dev 
- tk8.3-doc 
- tk8.4 
- tk8.4-dev 
- tk8.4-doc 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Tk could be made to overrun a buffer when loading
certain images. If a user were tricked into opening a specially crafted
GIF image, remote attackers could cause a denial of service or execute
arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- tk8.0-8.0.5-11ubuntu0.1 (Ubuntu 6.06)
- tk8.0-dev-8.0.5-11ubuntu0.1 (Ubuntu 6.06)
- tk8.0-doc-8.0.5-11ubuntu0.1 (Ubuntu 6.06)
- tk8.3-8.3.5-6ubuntu3.1 (Ubuntu 7.10)
- tk8.3-dev-8.3.5-6ubuntu3.1 (Ubuntu 7.10)
- tk8.3-doc-8.3.5-6ubuntu3.1 (Ubuntu 7.10)
- tk8.4-8.4.16-2ubuntu1.1 (Ubuntu 8.04)
- tk8.4-dev-8.4.16-2ubuntu1.1 (Ubuntu 8.04)
- tk8.4-doc-8.4.16-2ubuntu1.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-0553");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "tk8.0", pkgver: "8.0.5-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tk8.0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to tk8.0-8.0.5-11ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "tk8.0-dev", pkgver: "8.0.5-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tk8.0-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to tk8.0-dev-8.0.5-11ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "tk8.0-doc", pkgver: "8.0.5-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tk8.0-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to tk8.0-doc-8.0.5-11ubuntu0.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "tk8.3", pkgver: "8.3.5-6ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tk8.3-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to tk8.3-8.3.5-6ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "tk8.3-dev", pkgver: "8.3.5-6ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tk8.3-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to tk8.3-dev-8.3.5-6ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "tk8.3-doc", pkgver: "8.3.5-6ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tk8.3-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to tk8.3-doc-8.3.5-6ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "tk8.4", pkgver: "8.4.16-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tk8.4-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to tk8.4-8.4.16-2ubuntu1.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "tk8.4-dev", pkgver: "8.4.16-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tk8.4-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to tk8.4-dev-8.4.16-2ubuntu1.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "tk8.4-doc", pkgver: "8.4.16-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tk8.4-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to tk8.4-doc-8.4.16-2ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
