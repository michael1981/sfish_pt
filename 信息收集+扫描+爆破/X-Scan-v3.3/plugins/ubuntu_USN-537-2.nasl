# This script was automatically generated from the 537-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28144);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "537-2");
script_summary(english:"Compiz vulnerability");
script_name(english:"USN537-2 : Compiz vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- compiz 
- compiz-core 
- compiz-dev 
- compiz-gnome 
- compiz-kde 
- compiz-plugins 
- libdecoration0 
- libdecoration0-dev 
');
script_set_attribute(attribute:'description', value: 'USN-537-1 fixed vulnerabilities in gnome-screensaver. The fixes were
incomplete, and only reduced the scope of the vulnerability, without
fully solving it. This update fixes related problems in compiz.

Original advisory details:

 Jens Askengren discovered that gnome-screensaver became confused when
 running under Compiz, and could lose keyboard lock focus. A local attacker
 could exploit this to bypass the user\'s locked screen saver.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- compiz-0.6.0+git20071008-0ubuntu1.1 (Ubuntu 7.10)
- compiz-core-0.6.0+git20071008-0ubuntu1.1 (Ubuntu 7.10)
- compiz-dev-0.6.0+git20071008-0ubuntu1.1 (Ubuntu 7.10)
- compiz-gnome-0.6.0+git20071008-0ubuntu1.1 (Ubuntu 7.10)
- compiz-kde-0.6.0+git20071008-0ubuntu1.1 (Ubuntu 7.10)
- compiz-plugins-0.6.0+git20071008-0ubuntu1.1 (Ubuntu 7.10)
- libdecoration0-0.6.0+git20071008-0ubuntu1.1 (Ubuntu 7.10)
- libdecoration0-dev-0.6.0+git20071008-0ubuntu1.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-3920");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "compiz", pkgver: "0.6.0+git20071008-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package compiz-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to compiz-0.6.0+git20071008-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "compiz-core", pkgver: "0.6.0+git20071008-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package compiz-core-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to compiz-core-0.6.0+git20071008-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "compiz-dev", pkgver: "0.6.0+git20071008-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package compiz-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to compiz-dev-0.6.0+git20071008-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "compiz-gnome", pkgver: "0.6.0+git20071008-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package compiz-gnome-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to compiz-gnome-0.6.0+git20071008-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "compiz-kde", pkgver: "0.6.0+git20071008-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package compiz-kde-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to compiz-kde-0.6.0+git20071008-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "compiz-plugins", pkgver: "0.6.0+git20071008-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package compiz-plugins-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to compiz-plugins-0.6.0+git20071008-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libdecoration0", pkgver: "0.6.0+git20071008-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdecoration0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libdecoration0-0.6.0+git20071008-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libdecoration0-dev", pkgver: "0.6.0+git20071008-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdecoration0-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libdecoration0-dev-0.6.0+git20071008-0ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
