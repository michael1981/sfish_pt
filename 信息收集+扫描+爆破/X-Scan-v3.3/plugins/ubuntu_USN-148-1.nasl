# This script was automatically generated from the 148-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20543);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "148-1");
script_summary(english:"zlib vulnerability");
script_name(english:"USN148-1 : zlib vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- zlib-bin 
- zlib1g 
- zlib1g-dev 
');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy discovered that zlib did not properly verify data
streams.  Decompressing certain invalid compressed files caused
corruption of internal data structures, which caused applications
which link to zlib to crash.  Specially crafted input might even have
allowed arbitrary code execution.

zlib is used by hundreds of server and client applications, so this
vulnerability could be exploited to cause Denial of Service attacks to
almost all services provided by an Ubuntu system.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- zlib-bin-1.2.2-4ubuntu1.1 (Ubuntu 5.04)
- zlib1g-1.2.2-4ubuntu1.1 (Ubuntu 5.04)
- zlib1g-dev-1.2.2-4ubuntu1.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-2096");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "zlib-bin", pkgver: "1.2.2-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package zlib-bin-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to zlib-bin-1.2.2-4ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "zlib1g", pkgver: "1.2.2-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package zlib1g-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to zlib1g-1.2.2-4ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "zlib1g-dev", pkgver: "1.2.2-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package zlib1g-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to zlib1g-dev-1.2.2-4ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
