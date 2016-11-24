# This script was automatically generated from the 107-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20493);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "107-1");
script_summary(english:"ipsec-tools vulnerability");
script_name(english:"USN107-1 : ipsec-tools vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ipsec-tools 
- racoon 
');
script_set_attribute(attribute:'description', value: 'Sebastian Krahmer discovered a Denial of Service vulnerability in the
racoon daemon. By sending specially crafted ISAKMP packets, a remote
attacker could trigger a buffer overflow which caused racoon to crash.

This update does not introduce any source code changes affecting the
ipsec-tools package.  It is necessary to update the version number of
the package in order to support an update to the "racoon" package.
Please note that racoon is not officially supported by Ubuntu (it is
in the "universe" component of the archive).');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ipsec-tools-0.3.3-1ubuntu0.1 (Ubuntu 4.10)
- racoon-0.3.3-1ubuntu0.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0398");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "ipsec-tools", pkgver: "0.3.3-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ipsec-tools-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ipsec-tools-0.3.3-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "racoon", pkgver: "0.3.3-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package racoon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to racoon-0.3.3-1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
