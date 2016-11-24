# This script was automatically generated from the 138-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20530);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "138-1");
script_summary(english:"gedit vulnerability");
script_name(english:"USN138-1 : gedit vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gedit 
- gedit-common 
- gedit-dev 
');
script_set_attribute(attribute:'description', value: 'A format string vulnerability has been discovered in gedit. Calling
the program with specially crafted file names caused a buffer
overflow, which could be exploited to execute arbitrary code with the
privileges of the gedit user.

This becomes security relevant if e. g. your web browser is configued
to open URLs in gedit. If you never open untrusted file names or URLs
in gedit, this flaw does not affect you.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gedit-2.10.2-0ubuntu2 (Ubuntu 5.04)
- gedit-common-2.10.2-0ubuntu2 (Ubuntu 5.04)
- gedit-dev-2.10.2-0ubuntu2 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2005-1686");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "gedit", pkgver: "2.10.2-0ubuntu2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gedit-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gedit-2.10.2-0ubuntu2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gedit-common", pkgver: "2.10.2-0ubuntu2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gedit-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gedit-common-2.10.2-0ubuntu2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gedit-dev", pkgver: "2.10.2-0ubuntu2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gedit-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gedit-dev-2.10.2-0ubuntu2
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
