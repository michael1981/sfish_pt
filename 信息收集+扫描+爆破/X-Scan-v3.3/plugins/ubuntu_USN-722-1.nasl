# This script was automatically generated from the 722-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38070);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "722-1");
script_summary(english:"sudo vulnerability");
script_name(english:"USN722-1 : sudo vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- sudo 
- sudo-ldap 
');
script_set_attribute(attribute:'description', value: 'Harald Koenig discovered that sudo did not correctly handle certain
privilege changes when handling groups.  If a local attacker belonged
to a group included in a "RunAs" list in the /etc/sudoers file, that
user could gain root privileges.  This was not an issue for the default
sudoers file shipped with Ubuntu.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- sudo-1.6.9p17-1ubuntu2.1 (Ubuntu 8.10)
- sudo-ldap-1.6.9p17-1ubuntu2.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0034");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "sudo", pkgver: "1.6.9p17-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sudo-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to sudo-1.6.9p17-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "sudo-ldap", pkgver: "1.6.9p17-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sudo-ldap-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to sudo-ldap-1.6.9p17-1ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
