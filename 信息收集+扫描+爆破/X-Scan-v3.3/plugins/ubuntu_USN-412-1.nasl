# This script was automatically generated from the 412-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28001);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "412-1");
script_summary(english:"GeoIP vulnerability");
script_name(english:"USN412-1 : GeoIP vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- geoip-bin 
- libgeoip-dev 
- libgeoip1 
');
script_set_attribute(attribute:'description', value: 'Dean Gaudet discovered that the GeoIP update tool did not validate the 
filename responses from the update server.  A malicious server, or 
man-in-the-middle system posing as a server, could write to arbitrary 
files with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- geoip-bin-1.3.17-1ubuntu0.1 (Ubuntu 6.10)
- libgeoip-dev-1.3.17-1ubuntu0.1 (Ubuntu 6.10)
- libgeoip1-1.3.17-1ubuntu0.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-0159");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "geoip-bin", pkgver: "1.3.17-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package geoip-bin-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to geoip-bin-1.3.17-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgeoip-dev", pkgver: "1.3.17-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgeoip-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgeoip-dev-1.3.17-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgeoip1", pkgver: "1.3.17-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgeoip1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgeoip1-1.3.17-1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
