# This script was automatically generated from the 378-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27960);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "378-1");
script_summary(english:"RPM vulnerability");
script_name(english:"USN378-1 : RPM vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- librpm-dev 
- librpm4 
- lsb-rpm 
- python-rpm 
- python2.4-rpm 
- rpm 
');
script_set_attribute(attribute:'description', value: 'An error was found in the RPM library\'s handling of query reports.  In 
some locales, certain RPM packages would cause the library to crash.  If 
a user was tricked into querying a specially crafted RPM package, the 
flaw could be exploited to execute arbitrary code with the user\'s 
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- librpm-dev-4.4.1-9.1ubuntu0.1 (Ubuntu 6.10)
- librpm4-4.4.1-9.1ubuntu0.1 (Ubuntu 6.10)
- lsb-rpm-4.4.1-9.1ubuntu0.1 (Ubuntu 6.10)
- python-rpm-4.4.1-9.1ubuntu0.1 (Ubuntu 6.10)
- python2.4-rpm-4.4.1-5ubuntu2.1 (Ubuntu 6.06)
- rpm-4.4.1-9.1ubuntu0.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-5466");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "librpm-dev", pkgver: "4.4.1-9.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package librpm-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to librpm-dev-4.4.1-9.1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "librpm4", pkgver: "4.4.1-9.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package librpm4-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to librpm4-4.4.1-9.1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "lsb-rpm", pkgver: "4.4.1-9.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lsb-rpm-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to lsb-rpm-4.4.1-9.1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "python-rpm", pkgver: "4.4.1-9.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-rpm-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to python-rpm-4.4.1-9.1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-rpm", pkgver: "4.4.1-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-rpm-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-rpm-4.4.1-5ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "rpm", pkgver: "4.4.1-9.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rpm-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to rpm-4.4.1-9.1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
