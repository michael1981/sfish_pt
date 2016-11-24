# This script was automatically generated from the 293-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27865);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "293-1");
script_summary(english:"gdm vulnerability");
script_name(english:"USN293-1 : gdm vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gdm" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'If the admin configured a gdm theme that provided an user list, any
user could activate the gdm setup program by first choosing the setup
option from the menu, clicking on the user list and entering his own
(instead of root\'s) password. This allowed normal users to configure
potentially dangerous features like remote or automatic login.

Please note that this does not affect a default Ubuntu installation,
since the default theme does not provide an user list. In Ubuntu 6.06
you additionally have to have the "ConfigAvailable" setting enabled in
gdm.conf to be vulnerable (it is disabled by default).

Ubuntu 5.04 is not affected by this flaw.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gdm-2.14.6-0ubuntu2.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2452");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "gdm", pkgver: "2.14.6-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gdm-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gdm-2.14.6-0ubuntu2.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
