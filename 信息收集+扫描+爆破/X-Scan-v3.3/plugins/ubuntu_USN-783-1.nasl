# This script was automatically generated from the 783-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39336);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "783-1");
script_summary(english:"ecryptfs-utils vulnerability");
script_name(english:"USN783-1 : ecryptfs-utils vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ecryptfs-utils 
- libecryptfs-dev 
- libecryptfs0 
');
script_set_attribute(attribute:'description', value: 'Chris Jones discovered that the eCryptfs support utilities would
report the mount passphrase into installation logs when an eCryptfs
home directory was selected during Ubuntu installation.  The logs are
only readable by the root user, but this still left the mount passphrase
unencrypted on disk, potentially leading to a loss of privacy.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ecryptfs-utils-73-0ubuntu6.1 (Ubuntu 9.04)
- libecryptfs-dev-73-0ubuntu6.1 (Ubuntu 9.04)
- libecryptfs0-73-0ubuntu6.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2009-1296");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "ecryptfs-utils", pkgver: "73-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ecryptfs-utils-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ecryptfs-utils-73-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libecryptfs-dev", pkgver: "73-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecryptfs-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libecryptfs-dev-73-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libecryptfs0", pkgver: "73-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecryptfs0-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libecryptfs0-73-0ubuntu6.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
