# This script was automatically generated from the 420-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28012);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "420-1");
script_summary(english:"KDE library vulnerability");
script_name(english:"USN420-1 : KDE library vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- kdelibs 
- kdelibs-bin 
- kdelibs-data 
- kdelibs-dbg 
- kdelibs4-dev 
- kdelibs4-doc 
- kdelibs4c2 
- kdelibs4c2-dbg 
- kdelibs4c2a 
');
script_set_attribute(attribute:'description', value: 'Jose Avila III and Robert Tasarz discovered that the KDE HTML library 
did not correctly parse HTML comments inside the "title" tag.  By 
tricking a Konqueror user into visiting a malicious website, an attacker 
could bypass cross-site scripting protections.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- kdelibs-3.5.5-0ubuntu3.1 (Ubuntu 6.10)
- kdelibs-bin-3.5.2-0ubuntu18.2 (Ubuntu 6.06)
- kdelibs-data-3.5.5-0ubuntu3.1 (Ubuntu 6.10)
- kdelibs-dbg-3.5.5-0ubuntu3.1 (Ubuntu 6.10)
- kdelibs4-dev-3.5.5-0ubuntu3.1 (Ubuntu 6.10)
- kdelibs4-doc-3.5.5-0ubuntu3.1 (Ubuntu 6.10)
- kdelibs4c2-3.4.3-0ubuntu2.2 (Ubuntu 5.10)
- kdelibs4c2-dbg-3.4.3-0ubuntu2.2 (Ubuntu 5.10)
- kdelibs4c2a-3.5.5-0ubuntu3.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2007-0537");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "kdelibs", pkgver: "3.5.5-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs-3.5.5-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdelibs-bin", pkgver: "3.5.2-0ubuntu18.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-bin-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdelibs-bin-3.5.2-0ubuntu18.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdelibs-data", pkgver: "3.5.5-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-data-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs-data-3.5.5-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdelibs-dbg", pkgver: "3.5.5-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs-dbg-3.5.5-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdelibs4-dev", pkgver: "3.5.5-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs4-dev-3.5.5-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdelibs4-doc", pkgver: "3.5.5-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-doc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs4-doc-3.5.5-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdelibs4c2", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdelibs4c2-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdelibs4c2-dbg", pkgver: "3.4.3-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4c2-dbg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdelibs4c2-dbg-3.4.3-0ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdelibs4c2a", pkgver: "3.5.5-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4c2a-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs4c2a-3.5.5-0ubuntu3.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
