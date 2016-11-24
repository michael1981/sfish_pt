# This script was automatically generated from the 439-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28036);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "439-2");
script_summary(english:"file vulnerability");
script_name(english:"USN439-2 : file vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- file 
- libmagic-dev 
- libmagic1 
- python-magic 
- python-magic-dbg 
- python2.4-magic 
');
script_set_attribute(attribute:'description', value: 'USN-439-1 fixed a vulnerability in file.  The original fix did not
fully solve the problem.  This update provides a more complete solution.

Original advisory details:

 Jean-Sebastien Guay-Leroux discovered that "file" did not correctly
 check the size of allocated heap memory. If a user were tricked into
 examining a specially crafted file with the "file" utility, a remote
 attacker could execute arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- file-4.19-1ubuntu2.1 (Ubuntu 7.04)
- libmagic-dev-4.19-1ubuntu2.1 (Ubuntu 7.04)
- libmagic1-4.19-1ubuntu2.1 (Ubuntu 7.04)
- python-magic-4.19-1ubuntu2.1 (Ubuntu 7.04)
- python-magic-dbg-4.19-1ubuntu2.1 (Ubuntu 7.04)
- python2.4-magic-4.16-0ubuntu3.2 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-2799");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "file", pkgver: "4.19-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package file-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to file-4.19-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libmagic-dev", pkgver: "4.19-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagic-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libmagic-dev-4.19-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libmagic1", pkgver: "4.19-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagic1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libmagic1-4.19-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "python-magic", pkgver: "4.19-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-magic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to python-magic-4.19-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "python-magic-dbg", pkgver: "4.19-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-magic-dbg-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to python-magic-dbg-4.19-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-magic", pkgver: "4.16-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-magic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-magic-4.16-0ubuntu3.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
