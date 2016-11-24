# This script was automatically generated from the 86-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20711);
script_version("$Revision: 1.12 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "86-1");
 script_cve_id("CVE-2005-0490");
script_summary(english:"curl vulnerability");
script_name(english:"USN86-1 : curl vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- curl 
- libcurl2 
- libcurl2-dbg 
- libcurl2-dev 
- libcurl2-gssapi 
');
script_set_attribute(attribute:'description', value: 'infamous41md discovered a buffer overflow in cURL\'s NT LAN Manager
(NTLM) authentication handling. By sending a specially crafted long
NTLM reply packet, a remote attacker could overflow the reply buffer.
This could lead to execution of arbitrary attacker specified code with
the privileges of the application using the cURL library.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- curl-7.12.0.is.7.11.2-1ubuntu0.1 (Ubuntu 4.10)
- libcurl2-7.12.0.is.7.11.2-1ubuntu0.1 (Ubuntu 4.10)
- libcurl2-dbg-7.12.0.is.7.11.2-1ubuntu0.1 (Ubuntu 4.10)
- libcurl2-dev-7.12.0.is.7.11.2-1ubuntu0.1 (Ubuntu 4.10)
- libcurl2-gssapi-7.12.0.is.7.11.2-1ubuntu0.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "curl", pkgver: "7.12.0.is.7.11.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package curl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to curl-7.12.0.is.7.11.2-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcurl2", pkgver: "7.12.0.is.7.11.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcurl2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcurl2-7.12.0.is.7.11.2-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcurl2-dbg", pkgver: "7.12.0.is.7.11.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcurl2-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcurl2-dbg-7.12.0.is.7.11.2-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcurl2-dev", pkgver: "7.12.0.is.7.11.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcurl2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcurl2-dev-7.12.0.is.7.11.2-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcurl2-gssapi", pkgver: "7.12.0.is.7.11.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcurl2-gssapi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcurl2-gssapi-7.12.0.is.7.11.2-1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
