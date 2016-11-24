# This script was automatically generated from the 457-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28055);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "457-1");
script_summary(english:"elinks vulnerability");
script_name(english:"USN457-1 : elinks vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- elinks 
- elinks-lite 
');
script_set_attribute(attribute:'description', value: 'Arnaud Giersch discovered that elinks incorrectly attempted to load 
gettext catalogs from a relative path.  If a user were tricked into 
running elinks from a specific directory, a local attacker could execute 
code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- elinks-0.11.1-1.2ubuntu2.1 (Ubuntu 7.04)
- elinks-lite-0.11.1-1.2ubuntu2.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-2027");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "elinks", pkgver: "0.11.1-1.2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package elinks-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to elinks-0.11.1-1.2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "elinks-lite", pkgver: "0.11.1-1.2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package elinks-lite-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to elinks-lite-0.11.1-1.2ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
