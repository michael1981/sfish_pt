# This script was automatically generated from the 838-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(41940);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "838-1");
script_summary(english:"dovecot vulnerabilities");
script_name(english:"USN838-1 : dovecot vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dovecot-common 
- dovecot-dev 
- dovecot-imapd 
- dovecot-pop3d 
- dovecot-postfix 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the ACL plugin in Dovecot would incorrectly handle
negative access rights. An attacker could exploit this flaw to access the
Dovecot server, bypassing the indended access restrictions. This only
affected Ubuntu 8.04 LTS. (CVE-2008-4577)

It was discovered that the ManageSieve service in Dovecot incorrectly
handled ".." in script names. A remote attacker could exploit this to read
and modify arbitrary sieve files on the server. This only affected Ubuntu
8.10. (CVE-2008-5301)

It was discovered that the Sieve plugin in Dovecot incorrectly handled
certain sieve scripts. An authenticated user could exploit this with a
crafted sieve script to cause a denial of service or possibly execute
arbitrary code. (CVE-2009-2632, CVE-2009-3235)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dovecot-common-1.1.11-0ubuntu4.1 (Ubuntu 9.04)
- dovecot-dev-1.1.11-0ubuntu4.1 (Ubuntu 9.04)
- dovecot-imapd-1.1.11-0ubuntu4.1 (Ubuntu 9.04)
- dovecot-pop3d-1.1.11-0ubuntu4.1 (Ubuntu 9.04)
- dovecot-postfix-1.1.11-0ubuntu4.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-4577","CVE-2008-5301","CVE-2009-2632","CVE-2009-3235");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "dovecot-common", pkgver: "1.1.11-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dovecot-common-1.1.11-0ubuntu4.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dovecot-dev", pkgver: "1.1.11-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dovecot-dev-1.1.11-0ubuntu4.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dovecot-imapd", pkgver: "1.1.11-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-imapd-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dovecot-imapd-1.1.11-0ubuntu4.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dovecot-pop3d", pkgver: "1.1.11-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-pop3d-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dovecot-pop3d-1.1.11-0ubuntu4.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dovecot-postfix", pkgver: "1.1.11-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-postfix-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dovecot-postfix-1.1.11-0ubuntu4.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
