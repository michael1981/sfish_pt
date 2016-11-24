# This script was automatically generated from the 847-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42082);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "847-1");
script_summary(english:"devscripts vulnerability");
script_name(english:"USN847-1 : devscripts vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "devscripts" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Raphael Geissert discovered that uscan, a part of devscripts, did not
properly sanitize its input when processing pathnames. If uscan processed a
crafted filename for a file on a remote server, an attacker could execute
arbitrary code with the privileges of the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- devscripts-2.10.39ubuntu7.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-2946");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "devscripts", pkgver: "2.10.39ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package devscripts-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to devscripts-2.10.39ubuntu7.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
