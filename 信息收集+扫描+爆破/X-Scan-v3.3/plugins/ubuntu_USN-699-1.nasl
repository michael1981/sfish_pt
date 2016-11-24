# This script was automatically generated from the 699-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37828);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "699-1");
script_summary(english:"blender vulnerabilities");
script_name(english:"USN699-1 : blender vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "blender" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'It was discovered that Blender did not correctly handle certain malformed
Radiance RGBE images. If a user were tricked into opening a .blend file
containing a specially crafted Radiance RGBE image, an attacker could execute
arbitrary code with the user\'s privileges. (CVE-2008-1102)

It was discovered that Blender did not properly sanitize the Python search
path. A local attacker could execute arbitrary code by inserting a specially
crafted Python file in the Blender working directory. (CVE-2008-4863)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- blender-2.41-1ubuntu4.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1102","CVE-2008-4863");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "blender", pkgver: "2.41-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package blender-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to blender-2.41-1ubuntu4.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
