# This script was automatically generated from the 810-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40490);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "810-1");
script_summary(english:"nss vulnerabilities");
script_name(english:"USN810-1 : nss vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libnss3-0d 
- libnss3-1d 
- libnss3-1d-dbg 
- libnss3-dev 
- libnss3-tools 
');
script_set_attribute(attribute:'description', value: 'Moxie Marlinspike discovered that NSS did not properly handle regular
expressions in certificate names. A remote attacker could create a
specially crafted certificate to cause a denial of service (via application
crash) or execute arbitrary code as the user invoking the program.
(CVE-2009-2404)

Moxie Marlinspike and Dan Kaminsky independently discovered that NSS did
not properly handle certificates with NULL characters in the certificate
name. An attacker could exploit this to perform a man in the middle attack
to view sensitive information or alter encrypted communications.
(CVE-2009-2408)

Dan Kaminsky discovered NSS would still accept certificates with MD2 hash
signatures. As a result, an attacker could potentially create a malicious
trusted certificate to impersonate another site. (CVE-2009-2409)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnss3-0d-3.12.3.1-0ubuntu0.9.04.1 (Ubuntu 9.04)
- libnss3-1d-3.12.3.1-0ubuntu0.9.04.1 (Ubuntu 9.04)
- libnss3-1d-dbg-3.12.3.1-0ubuntu0.9.04.1 (Ubuntu 9.04)
- libnss3-dev-3.12.3.1-0ubuntu0.9.04.1 (Ubuntu 9.04)
- libnss3-tools-3.12.3.1-0ubuntu0.9.04.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-2404","CVE-2009-2408","CVE-2009-2409");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libnss3-0d", pkgver: "3.12.3.1-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-0d-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libnss3-0d-3.12.3.1-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libnss3-1d", pkgver: "3.12.3.1-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-1d-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libnss3-1d-3.12.3.1-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libnss3-1d-dbg", pkgver: "3.12.3.1-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-1d-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libnss3-1d-dbg-3.12.3.1-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libnss3-dev", pkgver: "3.12.3.1-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libnss3-dev-3.12.3.1-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libnss3-tools", pkgver: "3.12.3.1-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-tools-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libnss3-tools-3.12.3.1-0ubuntu0.9.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
