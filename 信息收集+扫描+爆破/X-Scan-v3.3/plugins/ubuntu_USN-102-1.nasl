# This script was automatically generated from the 102-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20488);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "102-1");
script_summary(english:"sharutils vulnerabilities");
script_name(english:"USN102-1 : sharutils vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- sharutils 
- sharutils-doc 
');
script_set_attribute(attribute:'description', value: 'Shaun Colley discovered a buffer overflow in "shar" that was triggered
by output files (specified with -o) with names longer than 49
characters. This could be exploited to run arbitrary attacker
specified code on systems that automatically process uploaded files
with shar.

Ulf Harnhammar discovered that shar does not check the data length
returned by the \'wc\' command. However, it is believed that this cannot
actually be exploited on real systems.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- sharutils-4.2.1-10ubuntu0.1 (Ubuntu 4.10)
- sharutils-doc-4.2.1-10ubuntu0.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "sharutils", pkgver: "4.2.1-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sharutils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to sharutils-4.2.1-10ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "sharutils-doc", pkgver: "4.2.1-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sharutils-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to sharutils-doc-4.2.1-10ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
