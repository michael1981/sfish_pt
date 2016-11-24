# This script was automatically generated from the 768-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38647);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "768-1");
script_summary(english:"Apport vulnerability");
script_name(english:"USN768-1 : Apport vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- apport 
- apport-gtk 
- apport-qt 
- apport-retrace 
- python-apport 
- python-problem-report 
');
script_set_attribute(attribute:'description', value: 'Stephane Chazelas discovered that Apport did not safely remove files from
its crash report directory. If Apport had been enabled at some point, a
local attacker could remove arbitrary files from the system.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- apport-1.0-0ubuntu5.2 (Ubuntu 9.04)
- apport-gtk-1.0-0ubuntu5.2 (Ubuntu 9.04)
- apport-qt-1.0-0ubuntu5.2 (Ubuntu 9.04)
- apport-retrace-1.0-0ubuntu5.2 (Ubuntu 9.04)
- python-apport-1.0-0ubuntu5.2 (Ubuntu 9.04)
- python-problem-report-1.0-0ubuntu5.2 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2009-1295");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "apport", pkgver: "1.0-0ubuntu5.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apport-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apport-1.0-0ubuntu5.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apport-gtk", pkgver: "1.0-0ubuntu5.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apport-gtk-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apport-gtk-1.0-0ubuntu5.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apport-qt", pkgver: "1.0-0ubuntu5.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apport-qt-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apport-qt-1.0-0ubuntu5.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "apport-retrace", pkgver: "1.0-0ubuntu5.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apport-retrace-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to apport-retrace-1.0-0ubuntu5.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "python-apport", pkgver: "1.0-0ubuntu5.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-apport-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to python-apport-1.0-0ubuntu5.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "python-problem-report", pkgver: "1.0-0ubuntu5.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-problem-report-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to python-problem-report-1.0-0ubuntu5.2
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
