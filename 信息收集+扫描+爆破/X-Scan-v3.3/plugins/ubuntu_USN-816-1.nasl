# This script was automatically generated from the 816-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40590);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "816-1");
script_summary(english:"fetchmail vulnerability");
script_name(english:"USN816-1 : fetchmail vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- fetchmail 
- fetchmailconf 
');
script_set_attribute(attribute:'description', value: 'Moxie Marlinspike discovered that fetchmail did not properly handle
certificates with NULL characters in the certificate name. A remote
attacker could exploit this to perform a man in the middle attack to
view sensitive information or alter encrypted communications.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- fetchmail-6.3.8-11ubuntu3.1 (Ubuntu 8.10)
- fetchmailconf-6.3.8-11ubuntu3.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2009-2666");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "fetchmail", pkgver: "6.3.8-11ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fetchmail-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to fetchmail-6.3.8-11ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "fetchmailconf", pkgver: "6.3.8-11ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fetchmailconf-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to fetchmailconf-6.3.8-11ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
