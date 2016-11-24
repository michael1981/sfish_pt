# This script was automatically generated from the 488-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28089);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "488-1");
script_summary(english:"mod_perl vulnerability");
script_name(english:"USN488-1 : mod_perl vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libapache2-mod-perl2 
- libapache2-mod-perl2-dev 
- libapache2-mod-perl2-doc 
');
script_set_attribute(attribute:'description', value: 'Alex Solovey discovered that mod_perl did not correctly validate certain
regular expression matches.  A remote attacker could send a specially
crafted request to a web application using mod_perl, causing the web
server to monopolize CPU resources.  This could lead to a remote denial
of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libapache2-mod-perl2-2.0.2-2.3ubuntu1 (Ubuntu 7.04)
- libapache2-mod-perl2-dev-2.0.2-2.3ubuntu1 (Ubuntu 7.04)
- libapache2-mod-perl2-doc-2.0.2-2.3ubuntu1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-1349");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libapache2-mod-perl2", pkgver: "2.0.2-2.3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-perl2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libapache2-mod-perl2-2.0.2-2.3ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libapache2-mod-perl2-dev", pkgver: "2.0.2-2.3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-perl2-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libapache2-mod-perl2-dev-2.0.2-2.3ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libapache2-mod-perl2-doc", pkgver: "2.0.2-2.3ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-perl2-doc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libapache2-mod-perl2-doc-2.0.2-2.3ubuntu1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
