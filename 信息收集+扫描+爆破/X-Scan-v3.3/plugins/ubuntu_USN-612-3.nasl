# This script was automatically generated from the 612-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32357);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "612-3");
script_summary(english:"OpenVPN vulnerability");
script_name(english:"USN612-3 : OpenVPN vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "openvpn" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Once the update is applied, weak shared encryption keys and
   SSL/TLS certificates will be rejected where possible (though
   they cannot be detected in all cases). If you are using such
   keys or certificates, OpenVPN will not start and the keys or
   certificates will need to be regenerated.

   The safest course of action is to regenerate all OpenVPN
   certificates and key files, except where it can be established
   to a high degree of certainty that the certificate or shared key
   was generated on an unaffected system.

   Once the update is applied, you can check for weak OpenVPN shared
   secret keys with the openvpn-vulnkey command.

   $ openvpn-vulnkey /path/to/key

   OpenVPN shared keys can be regenerated using the openvpn command.

   $ openvpn --genkey --secret <file>

   Additionally, you can check for weak SSL/TLS certificates by
   installing openssl-blacklist via your package manager, and using
   the openssl-vulkey command.

   $ openssl-vulnkey /path/to/key

   Please note that openss
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- openvpn-2.0.9-8ubuntu0.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2008-0166");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "openvpn", pkgver: "2.0.9-8ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openvpn-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to openvpn-2.0.9-8ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
