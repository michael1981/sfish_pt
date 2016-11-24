# This script was automatically generated from the 781-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39312);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "781-1");
script_summary(english:"pidgin vulnerabilities");
script_name(english:"USN781-1 : pidgin vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- finch 
- finch-dev 
- gaim 
- libpurple-bin 
- libpurple-dev 
- libpurple0 
- pidgin 
- pidgin-data 
- pidgin-dbg 
- pidgin-dev 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Pidgin did not properly handle certain malformed
messages when sending a file using the XMPP protocol handler. If a user
were tricked into sending a file, a remote attacker could send a specially
crafted response and cause Pidgin to crash, or possibly execute arbitrary
code with user privileges. (CVE-2009-1373)

It was discovered that Pidgin did not properly handle certain malformed
messages in the QQ protocol handler. A remote attacker could send a
specially crafted message and cause Pidgin to crash. This issue only
affected Ubuntu 8.10 and 9.04. (CVE-2009-1374)

It was discovered that Pidgin did not properly handle certain malformed
messages in the XMPP and Sametime protocol handlers. A remote attacker
could send a specially crafted message and cause Pidgin to crash.
(CVE-2009-1375)

It was discovered that Pidgin did not properly handle certain malformed
messages in the MSN protocol handler. A remote attacker could send a
specially crafted message and possibly execute arbitrary code 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- finch-2.5.5-1ubuntu8.1 (Ubuntu 9.04)
- finch-dev-2.5.5-1ubuntu8.1 (Ubuntu 9.04)
- gaim-2.4.1-1ubuntu2.4 (Ubuntu 8.04)
- libpurple-bin-2.5.5-1ubuntu8.1 (Ubuntu 9.04)
- libpurple-dev-2.5.5-1ubuntu8.1 (Ubuntu 9.04)
- libpurple0-2.5.5-1ubuntu8.1 (Ubuntu 9.04)
- pidgin-2.5.5-1ubuntu8.1 (Ubuntu 9.04)
- pidgin-data-2.5.5-1ubuntu8.1 (Ubuntu 9.04)
- pidgin-dbg-2.5.5-1ubuntu8.1 (Ubuntu 9.04)
- pidgin-dev-2.5.5-1ubuntu8.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1373","CVE-2009-1374","CVE-2009-1375","CVE-2009-1376");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "finch", pkgver: "2.5.5-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package finch-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to finch-2.5.5-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "finch-dev", pkgver: "2.5.5-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package finch-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to finch-dev-2.5.5-1ubuntu8.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "gaim", pkgver: "2.4.1-1ubuntu2.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gaim-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to gaim-2.4.1-1ubuntu2.4
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpurple-bin", pkgver: "2.5.5-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpurple-bin-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpurple-bin-2.5.5-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpurple-dev", pkgver: "2.5.5-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpurple-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpurple-dev-2.5.5-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpurple0", pkgver: "2.5.5-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpurple0-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpurple0-2.5.5-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pidgin", pkgver: "2.5.5-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pidgin-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pidgin-2.5.5-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pidgin-data", pkgver: "2.5.5-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pidgin-data-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pidgin-data-2.5.5-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pidgin-dbg", pkgver: "2.5.5-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pidgin-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pidgin-dbg-2.5.5-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pidgin-dev", pkgver: "2.5.5-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pidgin-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pidgin-dev-2.5.5-1ubuntu8.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
