# This script was automatically generated from the 663-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38095);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "663-1");
script_summary(english:"system-tools-backends regression");
script_name(english:"USN663-1 : system-tools-backends regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- system-tools-backends 
- system-tools-backends-dev 
');
script_set_attribute(attribute:'description', value: 'It was discovered that passwords changed (or new users created) via the
"Users and Groups" tool were created with 3DES hashing.  This reduced the
security of stored user passwords, and was a regression from the correct
MD5 hashing.  This update fixes the problem; future password changes
will correct the hashing used.  We apologize for the inconvenience.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- system-tools-backends-2.6.0-1ubuntu1.1 (Ubuntu 8.10)
- system-tools-backends-dev-2.6.0-1ubuntu1.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "system-tools-backends", pkgver: "2.6.0-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package system-tools-backends-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to system-tools-backends-2.6.0-1ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "system-tools-backends-dev", pkgver: "2.6.0-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package system-tools-backends-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to system-tools-backends-dev-2.6.0-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
