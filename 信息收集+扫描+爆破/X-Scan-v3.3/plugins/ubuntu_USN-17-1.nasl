# This script was automatically generated from the 17-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20576);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "17-1");
script_summary(english:"passwd vulnerabilities");
script_name(english:"USN17-1 : passwd vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- login 
- passwd 
');
script_set_attribute(attribute:'description', value: 'Martin Schulze and Steve Grubb discovered a flaw in the authentication
input validation of the "chfn" and "chsh" programs. This allowed
logged in users with an expired password to change their real name and
their login shell without having to change their password.

This flaw cannot lead to privilege escalation and does not allow to
modify account properties of other users, so the impact is relatively
low.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- login-4.0.3-28.5ubuntu6.1 (Ubuntu 4.10)
- passwd-4.0.3-28.5ubuntu6.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2004-1001");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "login", pkgver: "4.0.3-28.5ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package login-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to login-4.0.3-28.5ubuntu6.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "passwd", pkgver: "4.0.3-28.5ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package passwd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to passwd-4.0.3-28.5ubuntu6.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
