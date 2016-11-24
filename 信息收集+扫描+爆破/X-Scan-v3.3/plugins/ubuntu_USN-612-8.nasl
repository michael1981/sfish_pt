# This script was automatically generated from the 612-8 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32431);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "612-8");
script_summary(english:"openssl-blacklist update");
script_name(english:"USN612-8 : openssl-blacklist update");
script_set_attribute(attribute:'synopsis', value: 'The remote package "openssl-blacklist" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-612-3 addressed a weakness in OpenSSL certificate and key
generation in OpenVPN by introducing openssl-blacklist to aid in
detecting vulnerable private keys. This update enhances the
openssl-vulnkey tool to check X.509 certificates as well, and
provides the corresponding update for Ubuntu 6.06. While the
OpenSSL in Ubuntu 6.06 was not vulnerable, openssl-blacklist is
now provided for Ubuntu 6.06 for checking certificates and keys
that may have been imported on these systems.

This update also includes the complete RSA-1024 and RSA-2048
blacklists for all Ubuntu architectures, as well as support for
other future blacklists for non-standard bit lengths.

You can check for weak SSL/TLS certificates by installing
openssl-blacklist via your package manager, and using the
openssl-vulnkey command.

$ openssl-vulnkey /path/to/certificate_or_key

This command can be used on public certificates and private keys
for any X.509 certificate or RSA key, including ones for web
servers, mail servers, OpenVPN, and others.
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openssl-blacklist-0.1-0ubuntu0.8.04.4 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "openssl-blacklist", pkgver: "0.1-0ubuntu0.8.04.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-blacklist-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openssl-blacklist-0.1-0ubuntu0.8.04.4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
