# This script was automatically generated from the 843-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42051);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "843-1");
script_summary(english:"backuppc vulnerability");
script_name(english:"USN843-1 : backuppc vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "backuppc" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'It was discovered that BackupPC did not restrict normal users from setting
the ClientNameAlias parameter. An authenticated user could exploit this to
gain access to unauthorized hosts. This update fixed the issue by
preventing normal users from modifying the ClientNameAlias configuration
parameter.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- backuppc-3.1.0-4ubuntu1.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-3369");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "backuppc", pkgver: "3.1.0-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package backuppc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to backuppc-3.1.0-4ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
