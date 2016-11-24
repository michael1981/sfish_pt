# This script was automatically generated from the 612-6 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32360);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "612-6");
script_summary(english:"OpenVPN regression");
script_name(english:"USN612-6 : OpenVPN regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- openssl-blacklist 
- openvpn 
');
script_set_attribute(attribute:'description', value: 'USN-612-3 addressed a weakness in OpenSSL certificate and keys
generation in OpenVPN by adding checks for vulnerable certificates
and keys to OpenVPN. A regression was introduced in OpenVPN when
using TLS and multi-client/server which caused OpenVPN to not start 
when using valid SSL certificates.

It was also found that openssl-vulnkey from openssl-blacklist
would fail when stderr was not available. This caused OpenVPN to
fail to start when used with applications such as NetworkManager.

This update fixes these problems. We apologize for the
inconvenience.

Original advisory details:

 A weakness has been discovered in the random number generator used
 by OpenSSL on Debian and Ubuntu systems.  As a result of this
 weakness, certain encryption keys are much more common than they
 should be, such that an attacker could guess the key through a
 brute-force attack given minimal knowledge of the system.  This
 particularly affects the use of encryption keys in OpenSSH, OpenVPN
 and SSL certificates.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openssl-blacklist-0.1-0ubuntu0.8.04.2 (Ubuntu 8.04)
- openvpn-2.0.9-8ubuntu0.2 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "openssl-blacklist", pkgver: "0.1-0ubuntu0.8.04.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-blacklist-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openssl-blacklist-0.1-0ubuntu0.8.04.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "openvpn", pkgver: "2.0.9-8ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openvpn-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to openvpn-2.0.9-8ubuntu0.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
