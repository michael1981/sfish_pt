# This script was automatically generated from the 10-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20485);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "10-1");
script_summary(english:"XML library vulnerabilities");
script_name(english:"USN10-1 : XML library vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libxml2 
- libxml2-dev 
- libxml2-doc 
- libxml2-python2.3 
- libxml2-utils 
');
script_set_attribute(attribute:'description', value: 'Several buffer overflows have been discovered in libxml2\'s FTP connection
and DNS resolution functions. Supplying very long FTP URLs or IP
addresses might result in execution of arbitrary code with the
privileges of the process using libxml2.

Since libxml2 is used in packages like php4-imagick, the vulnerability
also might lead to privilege escalation, like executing attacker
supplied code with a web server\'s privileges.

However, this does not affect the core XML parsing code, which is what
the majority of programs use this library for.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxml2-2.6.11-3ubuntu1.1 (Ubuntu 4.10)
- libxml2-dev-2.6.11-3ubuntu1.1 (Ubuntu 4.10)
- libxml2-doc-2.6.11-3ubuntu1.1 (Ubuntu 4.10)
- libxml2-python2.3-2.6.11-3ubuntu1.1 (Ubuntu 4.10)
- libxml2-utils-2.6.11-3ubuntu1.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2004-0981");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "libxml2", pkgver: "2.6.11-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml2-2.6.11-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxml2-dev", pkgver: "2.6.11-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml2-dev-2.6.11-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxml2-doc", pkgver: "2.6.11-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml2-doc-2.6.11-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxml2-python2.3", pkgver: "2.6.11-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-python2.3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml2-python2.3-2.6.11-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libxml2-utils", pkgver: "2.6.11-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-utils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libxml2-utils-2.6.11-3ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
