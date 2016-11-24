# This script was automatically generated from the 562-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29918);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "562-1");
script_summary(english:"opal vulnerability");
script_name(english:"USN562-1 : opal vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libopal-2.2.0 
- libopal-dbg 
- libopal-dev 
- libopal-doc 
- simpleopal 
');
script_set_attribute(attribute:'description', value: 'Jose Miguel Esparza discovered that certain SIP headers were not correctly
validated.  A remote attacker could send a specially crafted packet to
an application linked against opal (e.g. Ekiga) causing it to crash, leading
to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libopal-2.2.0-2.2.3.dfsg-2ubuntu2.1 (Ubuntu 7.04)
- libopal-dbg-2.2.3.dfsg-2ubuntu2.1 (Ubuntu 7.04)
- libopal-dev-2.2.3.dfsg-2ubuntu2.1 (Ubuntu 7.04)
- libopal-doc-2.2.3.dfsg-2ubuntu2.1 (Ubuntu 7.04)
- simpleopal-2.2.3.dfsg-2ubuntu2.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-4924");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libopal-2.2.0", pkgver: "2.2.3.dfsg-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopal-2.2.0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libopal-2.2.0-2.2.3.dfsg-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libopal-dbg", pkgver: "2.2.3.dfsg-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopal-dbg-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libopal-dbg-2.2.3.dfsg-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libopal-dev", pkgver: "2.2.3.dfsg-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopal-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libopal-dev-2.2.3.dfsg-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libopal-doc", pkgver: "2.2.3.dfsg-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopal-doc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libopal-doc-2.2.3.dfsg-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "simpleopal", pkgver: "2.2.3.dfsg-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package simpleopal-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to simpleopal-2.2.3.dfsg-2ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
