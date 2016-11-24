# This script was automatically generated from the 771-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38714);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "771-1");
script_summary(english:"libmodplug vulnerabilities");
script_name(english:"USN771-1 : libmodplug vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmodplug-dev 
- libmodplug0c2 
');
script_set_attribute(attribute:'description', value: 'It was discovered that libmodplug did not correctly handle certain
parameters when parsing MED media files. If a user or automated system were
tricked into opening a crafted MED file, an attacker could execute
arbitrary code with privileges of the user invoking the program.
(CVE-2009-1438)

Manfred Tremmel and Stanislav Brabec discovered that libmodplug did not
correctly handle long instrument names when parsing PAT sample files. If a
user or automated system were tricked into opening a crafted PAT file, an
attacker could cause a denial of service or execute arbitrary code with
privileges of the user invoking the program. This issue only affected
Ubuntu 9.04. (CVE-2009-1438)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmodplug-dev-0.8.4-3ubuntu1.1 (Ubuntu 9.04)
- libmodplug0c2-0.8.4-3ubuntu1.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-1438","CVE-2009-1513");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libmodplug-dev", pkgver: "0.8.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmodplug-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmodplug-dev-0.8.4-3ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmodplug0c2", pkgver: "0.8.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmodplug0c2-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmodplug0c2-0.8.4-3ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
