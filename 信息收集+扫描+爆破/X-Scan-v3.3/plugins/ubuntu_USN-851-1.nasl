# This script was automatically generated from the 851-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42208);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "851-1");
script_summary(english:"elinks vulnerabilities");
script_name(english:"USN851-1 : elinks vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- elinks 
- elinks-lite 
');
script_set_attribute(attribute:'description', value: 'Teemu Salmela discovered that Elinks did not properly validate input when
processing smb:// URLs. If a user were tricked into viewing a malicious
website and had smbclient installed, a remote attacker could execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2006-5925)

Jakub Wilk discovered a logic error in Elinks, leading to a buffer
overflow. If a user were tricked into viewing a malicious website, a remote
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2008-7224)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- elinks-0.10.6-1ubuntu3.4 (Ubuntu 6.06)
- elinks-lite-0.10.6-1ubuntu3.4 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-5925","CVE-2008-7224");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "elinks", pkgver: "0.10.6-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package elinks-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to elinks-0.10.6-1ubuntu3.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "elinks-lite", pkgver: "0.10.6-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package elinks-lite-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to elinks-lite-0.10.6-1ubuntu3.4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
