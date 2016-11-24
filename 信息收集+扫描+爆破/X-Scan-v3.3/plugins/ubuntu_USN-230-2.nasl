# This script was automatically generated from the 230-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20774);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "230-2");
script_summary(english:"xine-lib vulnerability");
script_name(english:"USN230-2 : xine-lib vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libxine-dev 
- libxine1 
- libxine1c2 
');
script_set_attribute(attribute:'description', value: 'USN-230-1 fixed a vulnerability in the ffmpeg library. The Xine
library contains a copy of the ffmpeg code, thus it is vulnerable to
the same flaw.

For reference, this is the original advisory:

  Simon Kilvington discovered a buffer overflow in the
  avcodec_default_get_buffer() function of the ffmpeg library. By
  tricking an user into opening a malicious movie which contains
  specially crafted PNG images, this could be exploited to execute
  arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxine-dev-1.0.1-1ubuntu10.2 (Ubuntu 5.10)
- libxine1-1.0-1ubuntu3.6 (Ubuntu 5.04)
- libxine1c2-1.0.1-1ubuntu10.2 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-4048");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libxine-dev", pkgver: "1.0.1-1ubuntu10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libxine-dev-1.0.1-1ubuntu10.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libxine1", pkgver: "1.0-1ubuntu3.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libxine1-1.0-1ubuntu3.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libxine1c2", pkgver: "1.0.1-1ubuntu10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libxine1c2-1.0.1-1ubuntu10.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
