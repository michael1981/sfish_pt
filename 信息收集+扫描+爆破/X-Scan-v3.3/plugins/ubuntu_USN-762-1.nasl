# This script was automatically generated from the 762-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37762);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "762-1");
script_summary(english:"apt vulnerabilities");
script_name(english:"USN762-1 : apt vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- apt 
- apt-doc 
- apt-transport-https 
- apt-utils 
- libapt-pkg-dev 
- libapt-pkg-doc 
');
script_set_attribute(attribute:'description', value: 'Alexandre Martani discovered that the APT daily cron script did not check
the return code of the date command. If a machine is configured for
automatic updates and is in a time zone where DST occurs at midnight, under
certain circumstances automatic updates might not be applied and could
become permanently disabled. (CVE-2009-1300)

Michael Casadevall discovered that APT did not properly verify repositories
signed with a revoked or expired key. If a repository were signed with only
an expired or revoked key and the signature was otherwise valid, APT would
consider the repository valid. (https://launchpad.net/bugs/356012)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- apt-0.7.14ubuntu6.1 (Ubuntu 8.10)
- apt-doc-0.7.14ubuntu6.1 (Ubuntu 8.10)
- apt-transport-https-0.7.14ubuntu6.1 (Ubuntu 8.10)
- apt-utils-0.7.14ubuntu6.1 (Ubuntu 8.10)
- libapt-pkg-dev-0.7.14ubuntu6.1 (Ubuntu 8.10)
- libapt-pkg-doc-0.7.14ubuntu6.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1300");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "apt", pkgver: "0.7.14ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apt-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to apt-0.7.14ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "apt-doc", pkgver: "0.7.14ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apt-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to apt-doc-0.7.14ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "apt-transport-https", pkgver: "0.7.14ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apt-transport-https-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to apt-transport-https-0.7.14ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "apt-utils", pkgver: "0.7.14ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apt-utils-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to apt-utils-0.7.14ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libapt-pkg-dev", pkgver: "0.7.14ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapt-pkg-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libapt-pkg-dev-0.7.14ubuntu6.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libapt-pkg-doc", pkgver: "0.7.14ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapt-pkg-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libapt-pkg-doc-0.7.14ubuntu6.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
