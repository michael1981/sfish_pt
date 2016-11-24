# This script was automatically generated from the 357-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27937);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "357-1");
script_summary(english:"Mono vulnerability");
script_name(english:"USN357-1 : Mono vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmono-dev 
- libmono0 
- mono 
- mono-assemblies-base 
- mono-classlib-1.0 
- mono-classlib-1.0-dbg 
- mono-classlib-2.0 
- mono-classlib-2.0-dbg 
- mono-common 
- mono-devel 
- mono-gac 
- mono-gmcs 
- mono-jay 
- mono-jit 
- mono-mcs 
- mono-utils 
');
script_set_attribute(attribute:'description', value: 'Sebastian Krahmer of the SuSE security team discovered that the
System.CodeDom.Compiler classes used temporary files in an insecure
way. This could allow a symbolic link attack to create or overwrite
arbitrary files with the privileges of the user invoking the program.
Under some circumstances, a local attacker could also exploit this to
inject arbitrary code into running Mono processes.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmono-dev-1.1.13.6-0ubuntu3.1 (Ubuntu 6.06)
- libmono0-1.1.13.6-0ubuntu3.1 (Ubuntu 6.06)
- mono-1.1.13.6-0ubuntu3.1 (Ubuntu 6.06)
- mono-assemblies-base-1.1.13.6-0ubuntu3.1 (Ubuntu 6.06)
- mono-classlib-1.0-1.1.13.6-0ubuntu3.1 (Ubuntu 6.06)
- mono-classlib-1.0-dbg-1.1.13.6-0ubuntu3.1 (Ubuntu 6.06)
- mono-classlib-2.0-1.1.13.6-0ubuntu3.1 (Ubuntu 6.06)
- mono-classlib-2.0-dbg-1.1.13.6-0ubuntu3.1 (Ubuntu 6.06)
- mono-common-1.1.13.6-0ubuntu3.1 (Ubuntu 6.06)
- mono-devel-1.1.13.6-0ubuntu3.1 (
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-5072");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libmono-dev", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmono-dev-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmono0", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmono0-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-assemblies-base", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-assemblies-base-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-assemblies-base-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-classlib-1.0", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-classlib-1.0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-classlib-1.0-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-classlib-1.0-dbg", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-classlib-1.0-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-classlib-1.0-dbg-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-classlib-2.0", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-classlib-2.0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-classlib-2.0-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-classlib-2.0-dbg", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-classlib-2.0-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-classlib-2.0-dbg-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-common", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-common-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-devel", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-devel-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-devel-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-gac", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-gac-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-gac-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-gmcs", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-gmcs-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-gmcs-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-jay", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-jay-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-jay-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-jit", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-jit-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-jit-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-mcs", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-mcs-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-mcs-1.1.13.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-utils", pkgver: "1.1.13.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-utils-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-utils-1.1.13.6-0ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
