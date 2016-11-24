# This script was automatically generated from the 300-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27875);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "300-1");
script_summary(english:"wv2 vulnerability");
script_name(english:"USN300-1 : wv2 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libwv2-1 
- libwv2-1c2 
- libwv2-dev 
');
script_set_attribute(attribute:'description', value: 'libwv2 did not sufficiently check the validity of its input. Certain
invalid Word documents caused a buffer overflow. By tricking a user
into opening a specially crafted Word file with an application that
uses libwv2, this could be exploited to execute arbitrary code with
the user\'s privileges.

The only packaged application using this library is KWord.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libwv2-1-0.2.2-1ubuntu1.1 (Ubuntu 5.04)
- libwv2-1c2-0.2.2-5ubuntu0.1 (Ubuntu 6.06)
- libwv2-dev-0.2.2-5ubuntu0.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2197");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "libwv2-1", pkgver: "0.2.2-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwv2-1-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libwv2-1-0.2.2-1ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libwv2-1c2", pkgver: "0.2.2-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwv2-1c2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libwv2-1c2-0.2.2-5ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libwv2-dev", pkgver: "0.2.2-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwv2-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libwv2-dev-0.2.2-5ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
