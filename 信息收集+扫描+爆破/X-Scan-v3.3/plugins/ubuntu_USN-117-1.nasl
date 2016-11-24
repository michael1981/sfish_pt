# This script was automatically generated from the 117-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20505);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "117-1");
script_summary(english:"cvs vulnerability");
script_name(english:"USN117-1 : cvs vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "cvs" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Alen Zukich discovered a buffer overflow in the processing of version
and author information in the CVS client. By tricking an user to
connect to a malicious CVS server, an attacker could exploit this to
execute arbitrary code with the privileges of the connecting user.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- cvs-1.12.9-9ubuntu0.1 (Ubuntu 4.10)
- cvs-1.12.9-9ubuntu0.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0753");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "cvs", pkgver: "1.12.9-9ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cvs-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cvs-1.12.9-9ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "cvs", pkgver: "1.12.9-9ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cvs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to cvs-1.12.9-9ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
