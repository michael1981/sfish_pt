# This script was automatically generated from the 292-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27864);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "292-1");
script_summary(english:"binutils vulnerability");
script_name(english:"USN292-1 : binutils vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- binutils 
- binutils-dev 
- binutils-doc 
- binutils-multiarch 
- binutils-static 
');
script_set_attribute(attribute:'description', value: 'CVE-2006-2362

Jesus Olmos Gonzalez discovered a buffer overflow in the Tektronix Hex
Format (TekHex) backend of the BFD library, such as used by the
\'strings\' utility. By tricking an user or automated system into
processing a specially crafted file with \'strings\' or a vulnerable
third-party application using the BFD library, this could be exploited
to crash the application, or possibly even execute arbitrary code with
the privileges of the user.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- binutils-2.16.1cvs20060117-1ubuntu2.1 (Ubuntu 6.06)
- binutils-dev-2.16.1cvs20060117-1ubuntu2.1 (Ubuntu 6.06)
- binutils-doc-2.16.1cvs20060117-1ubuntu2.1 (Ubuntu 6.06)
- binutils-multiarch-2.16.1cvs20060117-1ubuntu2.1 (Ubuntu 6.06)
- binutils-static-2.16.1cvs20060117-1ubuntu2.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2362");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "binutils", pkgver: "2.16.1cvs20060117-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to binutils-2.16.1cvs20060117-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "binutils-dev", pkgver: "2.16.1cvs20060117-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to binutils-dev-2.16.1cvs20060117-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "binutils-doc", pkgver: "2.16.1cvs20060117-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to binutils-doc-2.16.1cvs20060117-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "binutils-multiarch", pkgver: "2.16.1cvs20060117-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-multiarch-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to binutils-multiarch-2.16.1cvs20060117-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "binutils-static", pkgver: "2.16.1cvs20060117-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-static-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to binutils-static-2.16.1cvs20060117-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
