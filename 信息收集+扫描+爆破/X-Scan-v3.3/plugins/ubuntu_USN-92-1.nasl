# This script was automatically generated from the 92-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20718);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "92-1");
script_summary(english:"lesstif1-1 vulnerabilities");
script_name(english:"USN92-1 : lesstif1-1 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- lesstif-bin 
- lesstif-dev 
- lesstif-doc 
- lesstif1 
- lesstif2 
- lesstif2-dev 
');
script_set_attribute(attribute:'description', value: 'Several vulnerabilities have been found in the XPM image decoding
functions of the LessTif library. If an attacker tricked a user into
loading a malicious XPM image with an application that uses LessTif,
he could exploit this to execute arbitrary code in the context of the
user opening the image.

Ubuntu does not contain any server applications using LessTif, so
there is no possibility of privilege escalation.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- lesstif-bin-0.93.94-4ubuntu1.3 (Ubuntu 4.10)
- lesstif-dev-0.93.94-4ubuntu1.3 (Ubuntu 4.10)
- lesstif-doc-0.93.94-4ubuntu1.3 (Ubuntu 4.10)
- lesstif1-0.93.94-4ubuntu1.3 (Ubuntu 4.10)
- lesstif2-0.93.94-4ubuntu1.3 (Ubuntu 4.10)
- lesstif2-dev-0.93.94-4ubuntu1.3 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0605");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "lesstif-bin", pkgver: "0.93.94-4ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lesstif-bin-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif-bin-0.93.94-4ubuntu1.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "lesstif-dev", pkgver: "0.93.94-4ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lesstif-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif-dev-0.93.94-4ubuntu1.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "lesstif-doc", pkgver: "0.93.94-4ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lesstif-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif-doc-0.93.94-4ubuntu1.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "lesstif1", pkgver: "0.93.94-4ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lesstif1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif1-0.93.94-4ubuntu1.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "lesstif2", pkgver: "0.93.94-4ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lesstif2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif2-0.93.94-4ubuntu1.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "lesstif2-dev", pkgver: "0.93.94-4ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lesstif2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif2-dev-0.93.94-4ubuntu1.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
