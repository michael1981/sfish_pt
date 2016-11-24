# This script was automatically generated from the 128-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20518);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "128-1");
script_summary(english:"nasm vulnerability");
script_name(english:"USN128-1 : nasm vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "nasm" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Josh Bressers discovered a buffer overflow in the ieee_putascii()
function of nasm. If an attacker tricked a user into assembling a
malicious source file, they could exploit this to execute arbitrary
code with the privileges of the user that runs nasm.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- nasm-0.98.38-1ubuntu0.2 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-1194");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "nasm", pkgver: "0.98.38-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nasm-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to nasm-0.98.38-1ubuntu0.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
