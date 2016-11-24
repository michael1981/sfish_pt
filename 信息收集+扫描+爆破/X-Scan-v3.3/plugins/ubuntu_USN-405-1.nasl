# This script was automatically generated from the 405-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27993);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "405-1");
script_summary(english:"fetchmail vulnerability");
script_name(english:"USN405-1 : fetchmail vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- fetchmail 
- fetchmail-ssl 
- fetchmailconf 
');
script_set_attribute(attribute:'description', value: 'It was discovered that fetchmail did not correctly require TLS 
negotiation in certain situations.  This would result in a user\'s 
unencrypted password being sent across the network.

If fetchmail has been configured to use the "sslproto tls1", 
"sslcertck", or "sslfingerprint" options with a server that does not 
correctly support TLS negotiation, this update may cause fetchmail to 
(correctly) abort authentication.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- fetchmail-6.3.4-1ubuntu4.1 (Ubuntu 6.10)
- fetchmail-ssl-6.2.5-13ubuntu3.3 (Ubuntu 5.10)
- fetchmailconf-6.3.4-1ubuntu4.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2006-5867");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "fetchmail", pkgver: "6.3.4-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fetchmail-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to fetchmail-6.3.4-1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "fetchmail-ssl", pkgver: "6.2.5-13ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fetchmail-ssl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to fetchmail-ssl-6.2.5-13ubuntu3.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "fetchmailconf", pkgver: "6.3.4-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fetchmailconf-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to fetchmailconf-6.3.4-1ubuntu4.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
