# This script was automatically generated from the 434-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28029);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "434-1");
script_summary(english:"Ekiga vulnerability");
script_name(english:"USN434-1 : Ekiga vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ekiga 
- gnomemeeting 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Ekiga had format string vulnerabilities beyond 
those fixed in USN-426-1.  If a user was running Ekiga and listening for 
incoming calls, a remote attacker could send a crafted call request, and 
execute arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ekiga-2.0.3-0ubuntu3.2 (Ubuntu 6.10)
- gnomemeeting-1.2.2-1ubuntu1.2 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-0999");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "ekiga", pkgver: "2.0.3-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ekiga-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to ekiga-2.0.3-0ubuntu3.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "gnomemeeting", pkgver: "1.2.2-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnomemeeting-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gnomemeeting-1.2.2-1ubuntu1.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
