# This script was automatically generated from the 597-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31784);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "597-1");
script_summary(english:"OpenSSH vulnerability");
script_name(english:"USN597-1 : OpenSSH vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- openssh-client 
- openssh-server 
- ssh 
- ssh-askpass-gnome 
- ssh-krb5 
');
script_set_attribute(attribute:'description', value: 'Timo Juhani Lindfors discovered that the OpenSSH client, when port
forwarding was requested, would listen on any available address family.
A local attacker could exploit this flaw on systems with IPv6 enabled
to hijack connections, including X11 forwards.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openssh-client-4.6p1-5ubuntu0.2 (Ubuntu 7.10)
- openssh-server-4.6p1-5ubuntu0.2 (Ubuntu 7.10)
- ssh-4.6p1-5ubuntu0.2 (Ubuntu 7.10)
- ssh-askpass-gnome-4.6p1-5ubuntu0.2 (Ubuntu 7.10)
- ssh-krb5-4.6p1-5ubuntu0.2 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1483");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "openssh-client", pkgver: "4.6p1-5ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-client-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to openssh-client-4.6p1-5ubuntu0.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "openssh-server", pkgver: "4.6p1-5ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssh-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to openssh-server-4.6p1-5ubuntu0.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ssh", pkgver: "4.6p1-5ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ssh-4.6p1-5ubuntu0.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ssh-askpass-gnome", pkgver: "4.6p1-5ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-askpass-gnome-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ssh-askpass-gnome-4.6p1-5ubuntu0.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ssh-krb5", pkgver: "4.6p1-5ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ssh-krb5-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ssh-krb5-4.6p1-5ubuntu0.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
