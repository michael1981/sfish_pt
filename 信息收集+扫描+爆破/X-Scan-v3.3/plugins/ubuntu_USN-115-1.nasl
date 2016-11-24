# This script was automatically generated from the 115-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20503);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "115-1");
script_summary(english:"kdewebdev vulnerability");
script_name(english:"USN115-1 : kdewebdev vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- kdewebdev 
- kdewebdev-doc-html 
- kfilereplace 
- kimagemapeditor 
- klinkstatus 
- kommander 
- kommander-dev 
- kxsldbg 
- quanta 
- quanta-data 
');
script_set_attribute(attribute:'description', value: 'Eckhart Wörner discovered that Kommander opens files from remote and
possibly untrusted locations without user confirmation. Since
Kommander files can contain scripts, this would allow an attacker to
execute arbitrary code with the privileges of the user opening the
file.

The updated Kommander will not automatically open files from remote
locations, and files which do not end with ".kmdr" any more.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- kdewebdev-3.4.0-0ubuntu2.2 (Ubuntu 5.04)
- kdewebdev-doc-html-3.4.0-0ubuntu2.2 (Ubuntu 5.04)
- kfilereplace-3.4.0-0ubuntu2.2 (Ubuntu 5.04)
- kimagemapeditor-3.4.0-0ubuntu2.2 (Ubuntu 5.04)
- klinkstatus-3.4.0-0ubuntu2.2 (Ubuntu 5.04)
- kommander-3.4.0-0ubuntu2.2 (Ubuntu 5.04)
- kommander-dev-3.4.0-0ubuntu2.2 (Ubuntu 5.04)
- kxsldbg-3.4.0-0ubuntu2.2 (Ubuntu 5.04)
- quanta-3.4.0-0ubuntu2.2 (Ubuntu 5.04)
- quanta-data-3.4.0-0ubuntu2.2 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0754");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "kdewebdev", pkgver: "3.4.0-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdewebdev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdewebdev-3.4.0-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdewebdev-doc-html", pkgver: "3.4.0-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdewebdev-doc-html-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdewebdev-doc-html-3.4.0-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kfilereplace", pkgver: "3.4.0-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kfilereplace-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kfilereplace-3.4.0-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kimagemapeditor", pkgver: "3.4.0-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kimagemapeditor-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kimagemapeditor-3.4.0-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "klinkstatus", pkgver: "3.4.0-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package klinkstatus-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to klinkstatus-3.4.0-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kommander", pkgver: "3.4.0-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kommander-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kommander-3.4.0-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kommander-dev", pkgver: "3.4.0-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kommander-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kommander-dev-3.4.0-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kxsldbg", pkgver: "3.4.0-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kxsldbg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kxsldbg-3.4.0-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "quanta", pkgver: "3.4.0-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package quanta-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to quanta-3.4.0-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "quanta-data", pkgver: "3.4.0-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package quanta-data-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to quanta-data-3.4.0-0ubuntu2.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
