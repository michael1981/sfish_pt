# This script was automatically generated from the 859-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42817);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "859-1");
script_summary(english:"openjdk-6 vulnerabilities");
script_name(english:"USN859-1 : openjdk-6 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- icedtea-6-jre-cacao 
- icedtea6-plugin 
- openjdk-6-dbg 
- openjdk-6-demo 
- openjdk-6-doc 
- openjdk-6-jdk 
- openjdk-6-jre 
- openjdk-6-jre-headless 
- openjdk-6-jre-lib 
- openjdk-6-jre-zero 
- openjdk-6-source 
- openjdk-6-source-files 
');
script_set_attribute(attribute:'description', value: 'Dan Kaminsky discovered that SSL certificates signed with MD2 could be
spoofed given enough time.  As a result, an attacker could potentially
create a malicious trusted certificate to impersonate another site. This
update handles this issue by completely disabling MD2 for certificate
validation in OpenJDK. (CVE-2009-2409)

It was discovered that ICC profiles could be identified with
".." pathnames.  If a user were tricked into running a specially
crafted applet, a remote attacker could gain information about a local
system. (CVE-2009-3728)

Peter Vreugdenhil discovered multiple flaws in the processing of graphics
in the AWT library.  If a user were tricked into running a specially
crafted applet, a remote attacker could crash the application or run
arbitrary code with user privileges.  (CVE-2009-3869, CVE-2009-3871)

Multiple flaws were discovered in JPEG and BMP image handling.  If a user
were tricked into loading a specially crafted image, a remote attacker
could crash the application or run arbitrary code
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- icedtea-6-jre-cacao-6b16-1.6.1-3ubuntu1 (Ubuntu 9.10)
- icedtea6-plugin-6b16-1.6.1-3ubuntu1 (Ubuntu 9.10)
- openjdk-6-dbg-6b16-1.6.1-3ubuntu1 (Ubuntu 9.10)
- openjdk-6-demo-6b16-1.6.1-3ubuntu1 (Ubuntu 9.10)
- openjdk-6-doc-6b16-1.6.1-3ubuntu1 (Ubuntu 9.10)
- openjdk-6-jdk-6b16-1.6.1-3ubuntu1 (Ubuntu 9.10)
- openjdk-6-jre-6b16-1.6.1-3ubuntu1 (Ubuntu 9.10)
- openjdk-6-jre-headless-6b16-1.6.1-3ubuntu1 (Ubuntu 9.10)
- openjdk-6-jre-lib-6b16-1.6.1-3ubuntu1 (Ubuntu 9.10)
- openjdk-6-jre-zero-6b16
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-2409","CVE-2009-3728","CVE-2009-3869","CVE-2009-3871","CVE-2009-3873","CVE-2009-3874","CVE-2009-3875","CVE-2009-3876","CVE-2009-3877","CVE-2009-3879","CVE-2009-3880","CVE-2009-3881","CVE-2009-3882","CVE-2009-3883","CVE-2009-3884","CVE-2009-3885");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.10", pkgname: "icedtea-6-jre-cacao", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package icedtea-6-jre-cacao-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to icedtea-6-jre-cacao-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "icedtea6-plugin", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package icedtea6-plugin-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to icedtea6-plugin-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "openjdk-6-dbg", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-dbg-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to openjdk-6-dbg-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "openjdk-6-demo", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-demo-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to openjdk-6-demo-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "openjdk-6-doc", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-doc-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to openjdk-6-doc-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "openjdk-6-jdk", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jdk-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to openjdk-6-jdk-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "openjdk-6-jre", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to openjdk-6-jre-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "openjdk-6-jre-headless", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-headless-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to openjdk-6-jre-headless-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "openjdk-6-jre-lib", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-lib-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to openjdk-6-jre-lib-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "openjdk-6-jre-zero", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-zero-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to openjdk-6-jre-zero-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "openjdk-6-source", pkgver: "6b16-1.6.1-3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-source-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to openjdk-6-source-6b16-1.6.1-3ubuntu1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-source-files", pkgver: "6b14-1.4.1-0ubuntu12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-source-files-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-source-files-6b14-1.4.1-0ubuntu12
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
