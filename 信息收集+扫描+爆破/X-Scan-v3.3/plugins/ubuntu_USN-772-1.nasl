# This script was automatically generated from the 772-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38715);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "772-1");
script_summary(english:"mpfr vulnerability");
script_name(english:"USN772-1 : mpfr vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmpfr-dev 
- libmpfr-doc 
- libmpfr1ldbl 
');
script_set_attribute(attribute:'description', value: 'It was discovered that MPFR improperly handled string lengths in its print
routines. If a user or automated system were tricked into processing
specially crafted data with applications linked against MPFR, an attacker
could cause a denial of service or execute arbitrary code with privileges
of the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmpfr-dev-2.4.0-1ubuntu3.1 (Ubuntu 9.04)
- libmpfr-doc-2.4.0-1ubuntu3.1 (Ubuntu 9.04)
- libmpfr1ldbl-2.4.0-1ubuntu3.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-0757");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libmpfr-dev", pkgver: "2.4.0-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmpfr-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmpfr-dev-2.4.0-1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmpfr-doc", pkgver: "2.4.0-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmpfr-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmpfr-doc-2.4.0-1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmpfr1ldbl", pkgver: "2.4.0-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmpfr1ldbl-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmpfr1ldbl-2.4.0-1ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
