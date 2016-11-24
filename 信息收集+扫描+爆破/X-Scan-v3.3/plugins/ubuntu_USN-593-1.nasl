# This script was automatically generated from the 593-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31701);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "593-1");
script_summary(english:"Dovecot vulnerabilities");
script_name(english:"USN593-1 : Dovecot vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dovecot-common 
- dovecot-imapd 
- dovecot-pop3d 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the default configuration of dovecot could allow
access to any email files with group "mail" without verifying that a user
had valid rights.  An attacker able to create symlinks in their mail
directory could exploit this to read or delete another user\'s email.
(CVE-2008-1199)

By default, dovecot passed special characters to the underlying
authentication systems.  While Ubuntu releases of dovecot are not known
to be vulnerable, the authentication routine was proactively improved
to avoid potential future problems.  (CVE-2008-1218)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dovecot-common-1.0.5-1ubuntu2.2 (Ubuntu 7.10)
- dovecot-imapd-1.0.5-1ubuntu2.2 (Ubuntu 7.10)
- dovecot-pop3d-1.0.5-1ubuntu2.2 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-1199","CVE-2008-1218");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "dovecot-common", pkgver: "1.0.5-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to dovecot-common-1.0.5-1ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "dovecot-imapd", pkgver: "1.0.5-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-imapd-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to dovecot-imapd-1.0.5-1ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "dovecot-pop3d", pkgver: "1.0.5-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-pop3d-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to dovecot-pop3d-1.0.5-1ubuntu2.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
