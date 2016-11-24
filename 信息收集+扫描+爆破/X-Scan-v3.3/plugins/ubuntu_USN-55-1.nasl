# This script was automatically generated from the 55-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20673);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "55-1");
script_summary(english:"imlib2 vulnerabilities");
script_name(english:"USN55-1 : imlib2 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libimlib2 
- libimlib2-dev 
');
script_set_attribute(attribute:'description', value: 'Recently, Pavel Kankovsky discovered several buffer overflows in imlib
which were fixed in USN-53-1. It was found that imlib2 was vulnerable
to similar issues.

If an attacker tricked a user into loading a malicious XPM or BMP
image, he could exploit this to execute arbitrary code in the context
of the user opening the image.

These vulnerabilities might also lead to privilege escalation if a
privileged server process is using this library; for example, a PHP
script on the web server which does automatic image processing might
use the php-imlib package, in which case a remote attacker could
possibly execute arbitrary code with the web server\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libimlib2-1.1.0-12ubuntu2.1 (Ubuntu 4.10)
- libimlib2-dev-1.1.0-12ubuntu2.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2004-1025","CVE-2004-1026");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "libimlib2", pkgver: "1.1.0-12ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libimlib2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libimlib2-1.1.0-12ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libimlib2-dev", pkgver: "1.1.0-12ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libimlib2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libimlib2-dev-1.1.0-12ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
