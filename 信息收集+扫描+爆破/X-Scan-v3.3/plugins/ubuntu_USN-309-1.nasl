# This script was automatically generated from the 309-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27884);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "309-1");
script_summary(english:"libmms vulnerability");
script_name(english:"USN309-1 : libmms vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmms-dev 
- libmms0 
');
script_set_attribute(attribute:'description', value: 'Several buffer overflows were found in libmms. By tricking a user into
opening a specially crafted remote multimedia stream with an
application using libmms, a remote attacker could overwrite an
arbitrary memory portion with zeros, thereby crashing the program.

In Ubuntu 5.10, this affects the GStreamer MMS plugin
(gstreamer0.8-mms). Other Ubuntu releases do not support this library.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmms-dev-0.1-0ubuntu1.1 (Ubuntu 5.10)
- libmms0-0.1-0ubuntu1.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2200");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libmms-dev", pkgver: "0.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmms-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmms-dev-0.1-0ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmms0", pkgver: "0.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmms0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmms0-0.1-0ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
