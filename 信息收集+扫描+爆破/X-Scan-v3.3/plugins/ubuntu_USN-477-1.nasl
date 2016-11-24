# This script was automatically generated from the 477-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28078);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "477-1");
script_summary(english:"krb5 vulnerabilities");
script_name(english:"USN477-1 : krb5 vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'Wei Wang discovered that the krb5 RPC library did not correctly handle
certain error conditions.  A remote attacker could cause kadmind to free
an uninitialized pointer, leading to a denial of service or possibly
execution of arbitrary code with root privileges. (CVE-2007-2442)

Wei Wang discovered that the krb5 RPC library did not correctly check
the size of certain communications.  A remote attacker could send a
specially crafted request to kadmind and execute arbitrary code with
root privileges. (CVE-2007-2443)

It was discovered that the kadmind service could be made to overflow its
stack.  A remote attacker could send a specially crafted request and
execute arbitrary code with root privileges. (CVE-2007-2798)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- krb5-admin-server-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- krb5-clients-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- krb5-doc-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- krb5-ftpd-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- krb5-kdc-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- krb5-rsh-server-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- krb5-telnetd-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- krb5-user-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- libkadm55-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- libkrb5-dbg-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- libkrb5-dev-1.4.4-5ubuntu3.1 (Ubuntu 7.04)
- 
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-2442","CVE-2007-2443","CVE-2007-2798");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "krb5-admin-server", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-admin-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to krb5-admin-server-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "krb5-clients", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-clients-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to krb5-clients-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "krb5-doc", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-doc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to krb5-doc-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "krb5-ftpd", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-ftpd-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to krb5-ftpd-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "krb5-kdc", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-kdc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to krb5-kdc-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "krb5-rsh-server", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-rsh-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to krb5-rsh-server-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "krb5-telnetd", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-telnetd-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to krb5-telnetd-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "krb5-user", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package krb5-user-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to krb5-user-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libkadm55", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkadm55-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libkadm55-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libkrb5-dbg", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkrb5-dbg-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libkrb5-dbg-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libkrb5-dev", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkrb5-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libkrb5-dev-1.4.4-5ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libkrb53", pkgver: "1.4.4-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkrb53-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libkrb53-1.4.4-5ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
