# This script was automatically generated from the 521-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28126);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "521-1");
script_summary(english:"libmodplug vulnerability");
script_name(english:"USN521-1 : libmodplug vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmodplug-dev 
- libmodplug0c2 
');
script_set_attribute(attribute:'description', value: 'Luigi Auriemma discovered that libmodplug did not properly sanitize
its input. A specially crafted AMF file could be used to exploit this
situation to cause buffer overflows and possibly execute arbitrary code
as the user.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmodplug-dev-0.7-5ubuntu0.6.10.1 (Ubuntu 6.10)
- libmodplug0c2-0.7-5ubuntu0.6.10.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4192");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libmodplug-dev", pkgver: "0.7-5ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmodplug-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmodplug-dev-0.7-5ubuntu0.6.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libmodplug0c2", pkgver: "0.7-5ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmodplug0c2-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmodplug0c2-0.7-5ubuntu0.6.10.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
