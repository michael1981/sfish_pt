# This script was automatically generated from the 353-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27934);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "353-2");
script_summary(english:"OpenSSL vulnerability");
script_name(english:"USN353-2 : OpenSSL vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libssl-dev 
- libssl0.9.7 
- libssl0.9.8 
- libssl0.9.8-dbg 
- openssl 
');
script_set_attribute(attribute:'description', value: 'USN-353-1 fixed several vulnerabilities in OpenSSL. However, Mark J
Cox noticed that the applied patch for CVE-2006-2940 was flawed. This
update corrects that patch.

For reference, this is the relevant part of the original advisory:

  Certain types of public key could take disproportionate amounts of
  time to process. The library now limits the maximum key exponent
  size to avoid Denial of Service attacks. (CVE-2006-2940)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libssl-dev-0.9.8a-7ubuntu0.3 (Ubuntu 6.06)
- libssl0.9.7-0.9.7g-1ubuntu1.5 (Ubuntu 5.10)
- libssl0.9.8-0.9.8a-7ubuntu0.3 (Ubuntu 6.06)
- libssl0.9.8-dbg-0.9.8a-7ubuntu0.3 (Ubuntu 6.06)
- openssl-0.9.8a-7ubuntu0.3 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2940");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libssl-dev", pkgver: "0.9.8a-7ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libssl-dev-0.9.8a-7ubuntu0.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libssl0.9.7", pkgver: "0.9.7g-1ubuntu1.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libssl0.9.7-0.9.7g-1ubuntu1.5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libssl0.9.8", pkgver: "0.9.8a-7ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libssl0.9.8-0.9.8a-7ubuntu0.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libssl0.9.8-dbg", pkgver: "0.9.8a-7ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libssl0.9.8-dbg-0.9.8a-7ubuntu0.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openssl", pkgver: "0.9.8a-7ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openssl-0.9.8a-7ubuntu0.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
