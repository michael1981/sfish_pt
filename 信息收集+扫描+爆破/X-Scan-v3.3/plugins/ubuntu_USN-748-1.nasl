# This script was automatically generated from the 748-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36366);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "748-1");
script_summary(english:"openjdk-6 vulnerabilities");
script_name(english:"USN748-1 : openjdk-6 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- icedtea6-plugin 
- openjdk-6-dbg 
- openjdk-6-demo 
- openjdk-6-doc 
- openjdk-6-jdk 
- openjdk-6-jre 
- openjdk-6-jre-headless 
- openjdk-6-jre-lib 
- openjdk-6-source 
- openjdk-6-source-files 
');
script_set_attribute(attribute:'description', value: 'It was discovered that font creation could leak temporary files.
If a user were tricked into loading a malicious program or applet,
a remote attacker could consume disk space, leading to a denial of
service. (CVE-2006-2426, CVE-2009-1100)

It was discovered that the lightweight HttpServer did not correctly close
files on dataless connections.  A remote attacker could send specially
crafted requests, leading to a denial of service. (CVE-2009-1101)

Certain 64bit Java actions would crash an application.  A local attacker
might be able to cause a denial of service. (CVE-2009-1102)

It was discovered that LDAP connections did not close correctly.
A remote attacker could send specially crafted requests, leading to a
denial of service.  (CVE-2009-1093)

Java LDAP routines did not unserialize certain data correctly.  A remote
attacker could send specially crafted requests that could lead to
arbitrary code execution. (CVE-2009-1094)

Java did not correctly check certain JAR headers.  If a user or
automated system we
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- icedtea6-plugin-6b12-0ubuntu6.4 (Ubuntu 8.10)
- openjdk-6-dbg-6b12-0ubuntu6.4 (Ubuntu 8.10)
- openjdk-6-demo-6b12-0ubuntu6.4 (Ubuntu 8.10)
- openjdk-6-doc-6b12-0ubuntu6.4 (Ubuntu 8.10)
- openjdk-6-jdk-6b12-0ubuntu6.4 (Ubuntu 8.10)
- openjdk-6-jre-6b12-0ubuntu6.4 (Ubuntu 8.10)
- openjdk-6-jre-headless-6b12-0ubuntu6.4 (Ubuntu 8.10)
- openjdk-6-jre-lib-6b12-0ubuntu6.4 (Ubuntu 8.10)
- openjdk-6-source-6b12-0ubuntu6.4 (Ubuntu 8.10)
- openjdk-6-source-files-6b12-0ubuntu6.4 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2426","CVE-2009-1093","CVE-2009-1094","CVE-2009-1095","CVE-2009-1096","CVE-2009-1097","CVE-2009-1098","CVE-2009-1100","CVE-2009-1101","CVE-2009-1102");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "icedtea6-plugin", pkgver: "6b12-0ubuntu6.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package icedtea6-plugin-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to icedtea6-plugin-6b12-0ubuntu6.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-dbg", pkgver: "6b12-0ubuntu6.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-dbg-6b12-0ubuntu6.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-demo", pkgver: "6b12-0ubuntu6.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-demo-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-demo-6b12-0ubuntu6.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-doc", pkgver: "6b12-0ubuntu6.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-doc-6b12-0ubuntu6.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-jdk", pkgver: "6b12-0ubuntu6.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jdk-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-jdk-6b12-0ubuntu6.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-jre", pkgver: "6b12-0ubuntu6.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-jre-6b12-0ubuntu6.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-jre-headless", pkgver: "6b12-0ubuntu6.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-headless-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-jre-headless-6b12-0ubuntu6.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-jre-lib", pkgver: "6b12-0ubuntu6.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-lib-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-jre-lib-6b12-0ubuntu6.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-source", pkgver: "6b12-0ubuntu6.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-source-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-source-6b12-0ubuntu6.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-source-files", pkgver: "6b12-0ubuntu6.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-source-files-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-source-files-6b12-0ubuntu6.4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
