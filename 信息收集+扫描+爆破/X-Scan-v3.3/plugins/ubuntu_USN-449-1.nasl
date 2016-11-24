# This script was automatically generated from the 449-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28046);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "449-1");
script_summary(english:"krb5 vulnerabilities");
script_name(english:"USN449-1 : krb5 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- krb5-admin-server 
- krb5-clients 
- krb5-doc 
- krb5-ftpd 
- krb5-kdc 
- krb5-rsh-server 
- krb5-telnetd 
- krb5-user 
- libkadm55 
- libkrb5-dbg 
- libkrb5-dev 
- libkrb53 
');
script_set_attribute(attribute:'description', value: 'The krb5 telnet service did not appropriately verify user names.  A 
remote attacker could log in as the root user by requesting a specially 
crafted user name. (CVE-2007-0956)

The krb5 syslog library did not correctly verify the size of log 
messages.  A remote attacker could send a specially crafted message and 
execute arbitrary code with root privileges. (CVE-2007-0957)

The krb5 administration service was vulnerable to a double-free in the 
GSS RPC library.  A remote attacker could send a specially crafted 
request and execute arbitrary code with root privileges. (CVE-2007-1216)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- krb5-admin-server-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- krb5-clients-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- krb5-doc-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- krb5-ftpd-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- krb5-kdc-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- krb5-rsh-server-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- krb5-telnetd-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- krb5-user-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- libkadm55-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- libkrb5-dbg-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- libkrb5-dev-1.4.3-9ubuntu1.2 (Ubuntu 6.10)
- 
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-0956","CVE-2007-0957","CVE-2007-1216");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "krb5-admin-server", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-admin-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krb5-admin-server-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krb5-clients", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-clients-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krb5-clients-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krb5-doc", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-doc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krb5-doc-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krb5-ftpd", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-ftpd-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krb5-ftpd-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krb5-kdc", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-kdc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krb5-kdc-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krb5-rsh-server", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-rsh-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krb5-rsh-server-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krb5-telnetd", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-telnetd-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krb5-telnetd-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "krb5-user", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-user-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to krb5-user-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libkadm55", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkadm55-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libkadm55-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libkrb5-dbg", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkrb5-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libkrb5-dbg-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libkrb5-dev", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkrb5-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libkrb5-dev-1.4.3-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libkrb53", pkgver: "1.4.3-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkrb53-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libkrb53-1.4.3-9ubuntu1.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
