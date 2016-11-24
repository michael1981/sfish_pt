# This script was automatically generated from the 713-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37381);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "713-1");
script_summary(english:"openjdk-6 vulnerabilities");
script_name(english:"USN713-1 : openjdk-6 vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'It was discovered that Java did not correctly handle untrusted applets.
If a user were tricked into running a malicious applet, a remote attacker
could gain user privileges, or list directory contents. (CVE-2008-5347,
CVE-2008-5350)

It was discovered that Kerberos authentication and RSA public key
processing were not correctly handled in Java.  A remote attacker
could exploit these flaws to cause a denial of service. (CVE-2008-5348,
CVE-2008-5349)

It was discovered that Java accepted UTF-8 encodings that might be
handled incorrectly by certain applications.  A remote attacker could
bypass string filters, possible leading to other exploits. (CVE-2008-5351)

Overflows were discovered in Java JAR processing.  If a user or
automated system were tricked into processing a malicious JAR file,
a remote attacker could crash the application, leading to a denial of
service. (CVE-2008-5352, CVE-2008-5354)

It was discovered that Java calendar objects were not unserialized safely.
If a user or automated system were tri
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- icedtea6-plugin-6b12-0ubuntu6.1 (Ubuntu 8.10)
- openjdk-6-dbg-6b12-0ubuntu6.1 (Ubuntu 8.10)
- openjdk-6-demo-6b12-0ubuntu6.1 (Ubuntu 8.10)
- openjdk-6-doc-6b12-0ubuntu6.1 (Ubuntu 8.10)
- openjdk-6-jdk-6b12-0ubuntu6.1 (Ubuntu 8.10)
- openjdk-6-jre-6b12-0ubuntu6.1 (Ubuntu 8.10)
- openjdk-6-jre-headless-6b12-0ubuntu6.1 (Ubuntu 8.10)
- openjdk-6-jre-lib-6b12-0ubuntu6.1 (Ubuntu 8.10)
- openjdk-6-source-6b12-0ubuntu6.1 (Ubuntu 8.10)
- openjdk-6-source-files-6b12-0ubuntu6.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-5347","CVE-2008-5348","CVE-2008-5349","CVE-2008-5350","CVE-2008-5351","CVE-2008-5352","CVE-2008-5353","CVE-2008-5354","CVE-2008-5358","CVE-2008-5359","CVE-2008-5360");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "icedtea6-plugin", pkgver: "6b12-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package icedtea6-plugin-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to icedtea6-plugin-6b12-0ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-dbg", pkgver: "6b12-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-dbg-6b12-0ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-demo", pkgver: "6b12-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-demo-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-demo-6b12-0ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-doc", pkgver: "6b12-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-doc-6b12-0ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-jdk", pkgver: "6b12-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jdk-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-jdk-6b12-0ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-jre", pkgver: "6b12-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-jre-6b12-0ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-jre-headless", pkgver: "6b12-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-headless-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-jre-headless-6b12-0ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-jre-lib", pkgver: "6b12-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-lib-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-jre-lib-6b12-0ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-source", pkgver: "6b12-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-source-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-source-6b12-0ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openjdk-6-source-files", pkgver: "6b12-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-source-files-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openjdk-6-source-files-6b12-0ubuntu6.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
