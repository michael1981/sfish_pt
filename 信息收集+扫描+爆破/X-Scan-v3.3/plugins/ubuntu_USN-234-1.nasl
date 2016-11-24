# This script was automatically generated from the 234-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20778);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "234-1");
script_summary(english:"cpio vulnerability");
script_name(english:"USN234-1 : cpio vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "cpio" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Richard Harms discovered that cpio did not sufficiently validate file
properties when creating archives. Files with e. g. a very large size
caused a buffer overflow. By tricking a user or an automatic backup
system into putting a specially crafted file into a cpio archive, a
local attacker could probably exploit this to execute arbitrary code
with the privileges of the target user (which is likely root in an
automatic backup system).');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- cpio-2.5-1.2ubuntu1.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-4268");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "cpio", pkgver: "2.5-1.2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cpio-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to cpio-2.5-1.2ubuntu1.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
