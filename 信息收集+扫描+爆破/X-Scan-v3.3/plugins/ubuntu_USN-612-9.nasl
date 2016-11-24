# This script was automatically generated from the 612-9 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33198);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "612-9");
script_summary(english:"openssl-blacklist update");
script_name(english:"USN612-9 : openssl-blacklist update");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- openssl-blacklist 
- openssl-blacklist-extra 
');
script_set_attribute(attribute:'description', value: 'USN-612-3 addressed a weakness in OpenSSL certificate and key
generation in OpenVPN by introducing openssl-blacklist to aid in
detecting vulnerable private keys. This update enhances the
openssl-vulnkey tool to check Certificate Signing Requests, accept
input from STDIN, and check moduli without a certificate.

It was also discovered that additional moduli are vulnerable if
generated with OpenSSL 0.9.8g or higher. While it is believed that
there are few of these vulnerable moduli in use, this update
includes updated RSA-1024 and RSA-2048 blacklists. RSA-512
blacklists are also included in the new openssl-blacklist-extra
package.

You can check for weak SSL/TLS certificates by installing
openssl-blacklist via your package manager, and using the
openssl-vulnkey command.

$ openssl-vulnkey /path/to/certificate_or_key
$ cat /path/to/certificate_or_key | openssl-vulnkey -

You can also check if a modulus is vulnerable by specifying the
modulus and number of bits.

$ openssl-vulnkey -b bits -m modulus

These comma
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openssl-blacklist-0.3.3+0.4-0ubuntu0.8.04.1 (Ubuntu 8.04)
- openssl-blacklist-extra-0.3.3+0.4-0ubuntu0.8.04.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "openssl-blacklist", pkgver: "0.3.3+0.4-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-blacklist-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openssl-blacklist-0.3.3+0.4-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openssl-blacklist-extra", pkgver: "0.3.3+0.4-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-blacklist-extra-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openssl-blacklist-extra-0.3.3+0.4-0ubuntu0.8.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
