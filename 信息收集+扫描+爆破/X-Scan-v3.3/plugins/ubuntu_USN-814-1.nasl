# This script was automatically generated from the 814-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40547);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "814-1");
script_summary(english:"openjdk-6 vulnerabilities");
script_name(english:"USN814-1 : openjdk-6 vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'It was discovered that the XML HMAC signature system did not
correctly check certain lengths.  If an attacker sent a truncated
HMAC, it could bypass authentication, leading to potential privilege
escalation. (CVE-2009-0217)

It was discovered that certain variables could leak information.  If a
user were tricked into running a malicious Java applet, a remote attacker
could exploit this gain access to private information and potentially
run untrusted code. (CVE-2009-2475, CVE-2009-2690)

A flaw was discovered the OpenType checking.  If a user were tricked
into running a malicious Java applet, a remote attacker could bypass
access restrictions. (CVE-2009-2476)

It was discovered that the XML processor did not correctly check
recursion.  If a user or automated system were tricked into processing
a specially crafted XML, the system could crash, leading to a denial of
service. (CVE-2009-2625)

It was discovered that the Java audio subsystem did not correctly validate
certain parameters.  If a user were tricked in
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- icedtea-6-jre-cacao-6b14-1.4.1-0ubuntu11 (Ubuntu 9.04)
- icedtea6-plugin-6b14-1.4.1-0ubuntu11 (Ubuntu 9.04)
- openjdk-6-dbg-6b14-1.4.1-0ubuntu11 (Ubuntu 9.04)
- openjdk-6-demo-6b14-1.4.1-0ubuntu11 (Ubuntu 9.04)
- openjdk-6-doc-6b14-1.4.1-0ubuntu11 (Ubuntu 9.04)
- openjdk-6-jdk-6b14-1.4.1-0ubuntu11 (Ubuntu 9.04)
- openjdk-6-jre-6b14-1.4.1-0ubuntu11 (Ubuntu 9.04)
- openjdk-6-jre-headless-6b14-1.4.1-0ubuntu11 (Ubuntu 9.04)
- openjdk-6-jre-lib-6b14-1.4.1-0ubuntu11 (Ubuntu 9.04)
- openjdk-6-jre-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0217","CVE-2009-2475","CVE-2009-2476","CVE-2009-2625","CVE-2009-2670","CVE-2009-2671","CVE-2009-2672","CVE-2009-2673","CVE-2009-2674","CVE-2009-2675","CVE-2009-2676","CVE-2009-2689","CVE-2009-2690");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "icedtea-6-jre-cacao", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package icedtea-6-jre-cacao-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to icedtea-6-jre-cacao-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "icedtea6-plugin", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package icedtea6-plugin-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to icedtea6-plugin-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-dbg", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-dbg-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-demo", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-demo-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-demo-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-doc", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-doc-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-jdk", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jdk-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-jdk-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-jre", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-jre-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-jre-headless", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-headless-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-jre-headless-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-jre-lib", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-lib-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-jre-lib-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-jre-zero", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-jre-zero-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-jre-zero-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-source", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-source-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-source-6b14-1.4.1-0ubuntu11
');
}
found = ubuntu_check(osver: "9.04", pkgname: "openjdk-6-source-files", pkgver: "6b14-1.4.1-0ubuntu11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openjdk-6-source-files-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to openjdk-6-source-files-6b14-1.4.1-0ubuntu11
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
