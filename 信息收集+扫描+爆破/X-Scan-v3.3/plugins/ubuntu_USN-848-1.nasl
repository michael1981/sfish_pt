# This script was automatically generated from the 848-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42146);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "848-1");
script_summary(english:"zope3 vulnerabilities");
script_name(english:"USN848-1 : zope3 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- python-zopeinterface 
- python-zopeinterface-dbg 
- python2.4-zopeinterface 
- zope3 
- zope3-dbg 
- zope3-doc 
- zope3-sandbox 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the Zope Object Database (ZODB) database server
(ZEO) improperly filtered certain commands when a database is shared among
multiple applications or application instances. A remote attacker could
send malicious commands to the server and execute arbitrary code.
(CVE-2009-0668)

It was discovered that the Zope Object Database (ZODB) database server
(ZEO) did not handle authentication properly when a database is shared
among multiple applications or application instances. A remote attacker
could use this flaw to bypass security restrictions. (CVE-2009-0669)

It was discovered that Zope did not limit the number of new object ids a
client could request. A remote attacker could use this flaw to consume a
huge amount of resources, leading to a denial of service. (No CVE
identifier)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- python-zopeinterface-3.4.0-0ubuntu3.3 (Ubuntu 9.04)
- python-zopeinterface-dbg-3.4.0-0ubuntu3.3 (Ubuntu 9.04)
- python2.4-zopeinterface-3.2.1-1ubuntu1.2 (Ubuntu 6.06)
- zope3-3.4.0-0ubuntu3.3 (Ubuntu 9.04)
- zope3-dbg-3.4.0-0ubuntu3.3 (Ubuntu 9.04)
- zope3-doc-3.4.0-0ubuntu3.3 (Ubuntu 9.04)
- zope3-sandbox-3.4.0-0ubuntu3.3 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-0668","CVE-2009-0669");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "python-zopeinterface", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-zopeinterface-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to python-zopeinterface-3.4.0-0ubuntu3.3
');
}
found = ubuntu_check(osver: "9.04", pkgname: "python-zopeinterface-dbg", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-zopeinterface-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to python-zopeinterface-dbg-3.4.0-0ubuntu3.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-zopeinterface", pkgver: "3.2.1-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-zopeinterface-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-zopeinterface-3.2.1-1ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "zope3", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package zope3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to zope3-3.4.0-0ubuntu3.3
');
}
found = ubuntu_check(osver: "9.04", pkgname: "zope3-dbg", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package zope3-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to zope3-dbg-3.4.0-0ubuntu3.3
');
}
found = ubuntu_check(osver: "9.04", pkgname: "zope3-doc", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package zope3-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to zope3-doc-3.4.0-0ubuntu3.3
');
}
found = ubuntu_check(osver: "9.04", pkgname: "zope3-sandbox", pkgver: "3.4.0-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package zope3-sandbox-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to zope3-sandbox-3.4.0-0ubuntu3.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
