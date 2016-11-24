# This script was automatically generated from the 800-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39787);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "800-1");
script_summary(english:"irssi vulnerability");
script_name(english:"USN800-1 : irssi vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- irssi 
- irssi-dev 
- irssi-text 
');
script_set_attribute(attribute:'description', value: 'It was discovered that irssi did not properly check the length of strings
when processing WALLOPS messages. If a user connected to an IRC network
where an attacker had IRC operator privileges, a remote attacker could
cause a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- irssi-0.8.12-6ubuntu1.1 (Ubuntu 9.04)
- irssi-dev-0.8.12-6ubuntu1.1 (Ubuntu 9.04)
- irssi-text-0.8.10-1ubuntu1.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2009-1959");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "irssi", pkgver: "0.8.12-6ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package irssi-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to irssi-0.8.12-6ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "irssi-dev", pkgver: "0.8.12-6ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package irssi-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to irssi-dev-0.8.12-6ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "irssi-text", pkgver: "0.8.10-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package irssi-text-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to irssi-text-0.8.10-1ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
