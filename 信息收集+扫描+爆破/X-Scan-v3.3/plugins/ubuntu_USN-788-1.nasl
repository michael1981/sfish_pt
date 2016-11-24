# This script was automatically generated from the 788-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39419);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "788-1");
script_summary(english:"tomcat6 vulnerabilities");
script_name(english:"USN788-1 : tomcat6 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libservlet2.5-java 
- libservlet2.5-java-doc 
- libtomcat6-java 
- tomcat6 
- tomcat6-admin 
- tomcat6-common 
- tomcat6-docs 
- tomcat6-examples 
- tomcat6-user 
');
script_set_attribute(attribute:'description', value: 'Iida Minehiko discovered that Tomcat did not properly normalise paths. A
remote attacker could send specially crafted requests to the server and
bypass security restrictions, gaining access to sensitive content.
(CVE-2008-5515)

Yoshihito Fukuyama discovered that Tomcat did not properly handle errors
when the Java AJP connector and mod_jk load balancing are used. A remote
attacker could send specially crafted requests containing invalid headers
to the server and cause a temporary denial of service. (CVE-2009-0033)

D. Matscheko and T. Hackner discovered that Tomcat did not properly handle
malformed URL encoding of passwords when FORM authentication is used. A
remote attacker could exploit this in order to enumerate valid usernames.
(CVE-2009-0580)

Deniz Cevik discovered that Tomcat did not properly escape certain
parameters in the example calendar application which could result in
browsers becoming vulnerable to cross-site scripting attacks when
processing the output. With cross-site scripting vulnerabiliti
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libservlet2.5-java-6.0.18-0ubuntu6.1 (Ubuntu 9.04)
- libservlet2.5-java-doc-6.0.18-0ubuntu6.1 (Ubuntu 9.04)
- libtomcat6-java-6.0.18-0ubuntu6.1 (Ubuntu 9.04)
- tomcat6-6.0.18-0ubuntu6.1 (Ubuntu 9.04)
- tomcat6-admin-6.0.18-0ubuntu6.1 (Ubuntu 9.04)
- tomcat6-common-6.0.18-0ubuntu6.1 (Ubuntu 9.04)
- tomcat6-docs-6.0.18-0ubuntu6.1 (Ubuntu 9.04)
- tomcat6-examples-6.0.18-0ubuntu6.1 (Ubuntu 9.04)
- tomcat6-user-6.0.18-0ubuntu6.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2008-5515","CVE-2009-0033","CVE-2009-0580","CVE-2009-0781","CVE-2009-0783");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libservlet2.5-java", pkgver: "6.0.18-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libservlet2.5-java-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libservlet2.5-java-6.0.18-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libservlet2.5-java-doc", pkgver: "6.0.18-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libservlet2.5-java-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libservlet2.5-java-doc-6.0.18-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libtomcat6-java", pkgver: "6.0.18-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtomcat6-java-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libtomcat6-java-6.0.18-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "tomcat6", pkgver: "6.0.18-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tomcat6-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to tomcat6-6.0.18-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "tomcat6-admin", pkgver: "6.0.18-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tomcat6-admin-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to tomcat6-admin-6.0.18-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "tomcat6-common", pkgver: "6.0.18-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tomcat6-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to tomcat6-common-6.0.18-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "tomcat6-docs", pkgver: "6.0.18-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tomcat6-docs-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to tomcat6-docs-6.0.18-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "tomcat6-examples", pkgver: "6.0.18-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tomcat6-examples-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to tomcat6-examples-6.0.18-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "tomcat6-user", pkgver: "6.0.18-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tomcat6-user-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to tomcat6-user-6.0.18-0ubuntu6.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
