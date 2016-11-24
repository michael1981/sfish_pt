# This script was automatically generated from the 447-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28044);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "447-1");
script_summary(english:"KDE library vulnerabilities");
script_name(english:"USN447-1 : KDE library vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'It was discovered that Konqueror did not correctly handle iframes from 
JavaScript.  If a user were tricked into visiting a malicious website, 
Konqueror could crash, resulting in a denial of service. (CVE-2007-1308)

A flaw was discovered in how Konqueror handled PASV FTP responses.  If a 
user were tricked into visiting a malicious FTP server, a remote 
attacker could perform a port-scan of machines within the user\'s 
network, leading to private information disclosure. (CVE-2007-1564)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- kdelibs-3.5.5-0ubuntu3.1.1 (Ubuntu 6.10)
- kdelibs-bin-3.5.2-0ubuntu18.3 (Ubuntu 6.06)
- kdelibs-data-3.5.5-0ubuntu3.1.1 (Ubuntu 6.10)
- kdelibs-dbg-3.5.5-0ubuntu3.1.1 (Ubuntu 6.10)
- kdelibs4-dev-3.5.5-0ubuntu3.1.1 (Ubuntu 6.10)
- kdelibs4-doc-3.5.5-0ubuntu3.1.1 (Ubuntu 6.10)
- kdelibs4c2-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kdelibs4c2-dbg-3.4.3-0ubuntu2.3 (Ubuntu 5.10)
- kdelibs4c2a-3.5.5-0ubuntu3.1.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-1308","CVE-2007-1564");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "kdelibs", pkgver: "3.5.5-0ubuntu3.1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs-3.5.5-0ubuntu3.1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "kdelibs-bin", pkgver: "3.5.2-0ubuntu18.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-bin-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to kdelibs-bin-3.5.2-0ubuntu18.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdelibs-data", pkgver: "3.5.5-0ubuntu3.1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-data-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs-data-3.5.5-0ubuntu3.1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdelibs-dbg", pkgver: "3.5.5-0ubuntu3.1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs-dbg-3.5.5-0ubuntu3.1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdelibs4-dev", pkgver: "3.5.5-0ubuntu3.1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs4-dev-3.5.5-0ubuntu3.1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdelibs4-doc", pkgver: "3.5.5-0ubuntu3.1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-doc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs4-doc-3.5.5-0ubuntu3.1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdelibs4c2", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdelibs4c2-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "kdelibs4c2-dbg", pkgver: "3.4.3-0ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4c2-dbg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to kdelibs4c2-dbg-3.4.3-0ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "kdelibs4c2a", pkgver: "3.5.5-0ubuntu3.1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4c2a-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to kdelibs4c2a-3.5.5-0ubuntu3.1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
