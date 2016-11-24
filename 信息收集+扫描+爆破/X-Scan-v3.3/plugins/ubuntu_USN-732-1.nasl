# This script was automatically generated from the 732-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36749);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "732-1");
script_summary(english:"dash vulnerability");
script_name(english:"USN732-1 : dash vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ash 
- dash 
');
script_set_attribute(attribute:'description', value: 'Wolfgang M. Reimer discovered that dash, when invoked as a login shell, would
source .profile files from the current directory. Local users may be able to
bypass security restrictions and gain root privileges by placing specially
crafted .profile files where they might get sourced by other dash users.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ash-0.5.4-9ubuntu1.1 (Ubuntu 8.10)
- dash-0.5.4-9ubuntu1.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0854");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "ash", pkgver: "0.5.4-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ash-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ash-0.5.4-9ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "dash", pkgver: "0.5.4-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dash-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to dash-0.5.4-9ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
