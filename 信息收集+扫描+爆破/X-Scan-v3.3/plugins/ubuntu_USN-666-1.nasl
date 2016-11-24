# This script was automatically generated from the 666-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37538);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "666-1");
script_summary(english:"dovecot vulnerability");
script_name(english:"USN666-1 : dovecot vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dovecot-common 
- dovecot-dev 
- dovecot-imapd 
- dovecot-pop3d 
');
script_set_attribute(attribute:'description', value: 'It was discovered that certain email headers were not correctly handled
by Dovecot.  If a remote attacker sent a specially crafted email to a
user with a mailbox managed by Dovecot, that user\'s mailbox would become
inaccessible through Dovecot, leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dovecot-common-1.1.4-0ubuntu1.2 (Ubuntu 8.10)
- dovecot-dev-1.1.4-0ubuntu1.2 (Ubuntu 8.10)
- dovecot-imapd-1.1.4-0ubuntu1.2 (Ubuntu 8.10)
- dovecot-pop3d-1.1.4-0ubuntu1.2 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2008-4907");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "dovecot-common", pkgver: "1.1.4-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-common-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to dovecot-common-1.1.4-0ubuntu1.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "dovecot-dev", pkgver: "1.1.4-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to dovecot-dev-1.1.4-0ubuntu1.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "dovecot-imapd", pkgver: "1.1.4-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-imapd-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to dovecot-imapd-1.1.4-0ubuntu1.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "dovecot-pop3d", pkgver: "1.1.4-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-pop3d-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to dovecot-pop3d-1.1.4-0ubuntu1.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
