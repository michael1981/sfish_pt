# This script was automatically generated from the 49-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20666);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "49-1");
script_summary(english:"debmake vulnerability");
script_name(english:"USN49-1 : debmake vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "debmake" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Javier Fernández-Sanguino Peña noticed that the debstd script from
debmake, a deprecated helper package for Debian packaging, created
temporary directories in an insecure manner. This could allow a
symlink attack to create or overwrite arbitrary files with the
privileges of the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- debmake-3.7.4ubuntu0.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2004-1179");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "debmake", pkgver: "3.7.4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package debmake-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to debmake-3.7.4ubuntu0.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
