# This script was automatically generated from the 365-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27945);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "365-1");
script_summary(english:"libksba vulnerability");
script_name(english:"USN365-1 : libksba vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libksba-dev 
- libksba8 
');
script_set_attribute(attribute:'description', value: 'A parsing failure was discovered in the handling of X.509 certificates 
that contained extra trailing data.  Malformed or malicious certificates
could cause services using libksba to crash, potentially creating a 
denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libksba-dev-0.9.9-2ubuntu0.5.04 (Ubuntu 5.04)
- libksba8-0.9.9-2ubuntu0.5.04 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-5111");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "libksba-dev", pkgver: "0.9.9-2ubuntu0.5.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libksba-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libksba-dev-0.9.9-2ubuntu0.5.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libksba8", pkgver: "0.9.9-2ubuntu0.5.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libksba8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libksba8-0.9.9-2ubuntu0.5.04
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
