# This script was automatically generated from the 649-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36855);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "649-1");
script_summary(english:"openssh vulnerabilities");
script_name(english:"USN649-1 : openssh vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- openssh-client 
- openssh-server 
- ssh 
- ssh-askpass-gnome 
- ssh-krb5 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the ForceCommand directive could be bypassed.
If a local user created a malicious ~/.ssh/rc file, they could execute
arbitrary commands as their user id.  This only affected Ubuntu 7.10.
(CVE-2008-1657)

USN-355-1 fixed vulnerabilities in OpenSSH.  It was discovered that the
fixes for this issue were incomplete.  A remote attacker could attempt
multiple logins, filling all available connection slots, leading to a
denial of service.  This only affected Ubuntu 6.06 and 7.04.
(CVE-2008-4109)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openssh-client-4.6p1-5ubuntu0.6 (Ubuntu 7.10)
- openssh-server-4.6p1-5ubuntu0.6 (Ubuntu 7.10)
- ssh-4.6p1-5ubuntu0.6 (Ubuntu 7.10)
- ssh-askpass-gnome-4.6p1-5ubuntu0.6 (Ubuntu 7.10)
- ssh-krb5-4.6p1-5ubuntu0.6 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-1657","CVE-2008-4109");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "openssh-client", pkgver: "4.6p1-5ubuntu0.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-client-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to openssh-client-4.6p1-5ubuntu0.6
');
}
found = ubuntu_check(osver: "7.10", pkgname: "openssh-server", pkgver: "4.6p1-5ubuntu0.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to openssh-server-4.6p1-5ubuntu0.6
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ssh", pkgver: "4.6p1-5ubuntu0.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ssh-4.6p1-5ubuntu0.6
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ssh-askpass-gnome", pkgver: "4.6p1-5ubuntu0.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-askpass-gnome-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ssh-askpass-gnome-4.6p1-5ubuntu0.6
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ssh-krb5", pkgver: "4.6p1-5ubuntu0.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-krb5-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ssh-krb5-4.6p1-5ubuntu0.6
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
