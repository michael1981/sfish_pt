# This script was automatically generated from the 487-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28088);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "487-1");
script_summary(english:"Dovecot vulnerability");
script_name(english:"USN487-1 : Dovecot vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dovecot-common 
- dovecot-imapd 
- dovecot-pop3d 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Dovecot, when configured to use non-system-user
spools and compressed folders, would allow directory traversals in
mailbox names.  Remote authenticated users could potentially read email
owned by other users.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dovecot-common-1.0.rc17-1ubuntu2.1 (Ubuntu 7.04)
- dovecot-imapd-1.0.rc17-1ubuntu2.1 (Ubuntu 7.04)
- dovecot-pop3d-1.0.rc17-1ubuntu2.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2007-2231");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "dovecot-common", pkgver: "1.0.rc17-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to dovecot-common-1.0.rc17-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "dovecot-imapd", pkgver: "1.0.rc17-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-imapd-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to dovecot-imapd-1.0.rc17-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "dovecot-pop3d", pkgver: "1.0.rc17-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-pop3d-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to dovecot-pop3d-1.0.rc17-1ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
