# This script was automatically generated from the 446-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28043);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "446-1");
script_summary(english:"NAS vulnerabilities");
script_name(english:"USN446-1 : NAS vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libaudio-dev 
- libaudio2 
- nas 
- nas-bin 
- nas-doc 
');
script_set_attribute(attribute:'description', value: 'Luigi Auriemma discovered multiple flaws in the Network Audio System 
server.  Remote attackers could send specially crafted network requests 
that could lead to a denial of service or execution of arbitrary code.  
Note that default Ubuntu installs do not include the NAS server.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libaudio-dev-1.8-2ubuntu0.1 (Ubuntu 6.10)
- libaudio2-1.8-2ubuntu0.1 (Ubuntu 6.10)
- nas-1.8-2ubuntu0.1 (Ubuntu 6.10)
- nas-bin-1.8-2ubuntu0.1 (Ubuntu 6.10)
- nas-doc-1.8-2ubuntu0.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-1543","CVE-2007-1544","CVE-2007-1545","CVE-2007-1546","CVE-2007-1547");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libaudio-dev", pkgver: "1.8-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libaudio-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libaudio-dev-1.8-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libaudio2", pkgver: "1.8-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libaudio2-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libaudio2-1.8-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nas", pkgver: "1.8-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nas-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nas-1.8-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nas-bin", pkgver: "1.8-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nas-bin-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nas-bin-1.8-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "nas-doc", pkgver: "1.8-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nas-doc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to nas-doc-1.8-2ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
