# This script was automatically generated from the 638-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(34059);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "638-1");
script_summary(english:"Yelp vulnerability");
script_name(english:"USN638-1 : Yelp vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "yelp" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Aaron Grattafiori discovered that the Gnome Help Viewer did not handle
format strings correctly when displaying certain error messages.  If a
user were tricked into opening a specially crafted URI, a remote attacker
could execute arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- yelp-2.22.1-0ubuntu2.8.04.3 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-3533");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "yelp", pkgver: "2.22.1-0ubuntu2.8.04.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package yelp-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to yelp-2.22.1-0ubuntu2.8.04.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
