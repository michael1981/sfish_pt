# This script was automatically generated from the 583-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31405);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "583-1");
script_summary(english:"Evolution vulnerability");
script_name(english:"USN583-1 : Evolution vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- evolution 
- evolution-common 
- evolution-dbg 
- evolution-dev 
- evolution-plugins 
- evolution-plugins-experimental 
');
script_set_attribute(attribute:'description', value: 'Ulf Harnhammar discovered that Evolution did not correctly handle format
strings when processing encrypted emails.  A remote attacker could exploit
this by sending a specially crafted email, resulting in arbitrary code
execution.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- evolution-2.12.1-0ubuntu1.1 (Ubuntu 7.10)
- evolution-common-2.12.1-0ubuntu1.1 (Ubuntu 7.10)
- evolution-dbg-2.12.1-0ubuntu1.1 (Ubuntu 7.10)
- evolution-dev-2.12.1-0ubuntu1.1 (Ubuntu 7.10)
- evolution-plugins-2.12.1-0ubuntu1.1 (Ubuntu 7.10)
- evolution-plugins-experimental-2.12.1-0ubuntu1.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-0072");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "evolution", pkgver: "2.12.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to evolution-2.12.1-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "evolution-common", pkgver: "2.12.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to evolution-common-2.12.1-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "evolution-dbg", pkgver: "2.12.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to evolution-dbg-2.12.1-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "evolution-dev", pkgver: "2.12.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to evolution-dev-2.12.1-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "evolution-plugins", pkgver: "2.12.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-plugins-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to evolution-plugins-2.12.1-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "evolution-plugins-experimental", pkgver: "2.12.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package evolution-plugins-experimental-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to evolution-plugins-experimental-2.12.1-0ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
