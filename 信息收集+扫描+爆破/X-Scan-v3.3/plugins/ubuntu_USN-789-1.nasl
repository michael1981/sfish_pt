# This script was automatically generated from the 789-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39491);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "789-1");
script_summary(english:"gst-plugins-good0.10 vulnerability");
script_name(english:"USN789-1 : gst-plugins-good0.10 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gstreamer0.10-esd 
- gstreamer0.10-plugins-good 
- gstreamer0.10-plugins-good-dbg 
- gstreamer0.10-plugins-good-doc 
- gstreamer0.10-pulseaudio 
');
script_set_attribute(attribute:'description', value: 'Tielei Wang discovered that GStreamer Good Plugins did not correctly handle
malformed PNG image files. If a user were tricked into opening a crafted
PNG image file with a GStreamer application, an attacker could cause a
denial of service via application crash, or possibly execute arbitrary code
with the privileges of the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gstreamer0.10-esd-0.10.14-1ubuntu0.1 (Ubuntu 9.04)
- gstreamer0.10-plugins-good-0.10.14-1ubuntu0.1 (Ubuntu 9.04)
- gstreamer0.10-plugins-good-dbg-0.10.14-1ubuntu0.1 (Ubuntu 9.04)
- gstreamer0.10-plugins-good-doc-0.10.14-1ubuntu0.1 (Ubuntu 9.04)
- gstreamer0.10-pulseaudio-0.10.14-1ubuntu0.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-1932");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "gstreamer0.10-esd", pkgver: "0.10.14-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-esd-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to gstreamer0.10-esd-0.10.14-1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "gstreamer0.10-plugins-good", pkgver: "0.10.14-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-plugins-good-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to gstreamer0.10-plugins-good-0.10.14-1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "gstreamer0.10-plugins-good-dbg", pkgver: "0.10.14-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-plugins-good-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to gstreamer0.10-plugins-good-dbg-0.10.14-1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "gstreamer0.10-plugins-good-doc", pkgver: "0.10.14-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-plugins-good-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to gstreamer0.10-plugins-good-doc-0.10.14-1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "gstreamer0.10-pulseaudio", pkgver: "0.10.14-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-pulseaudio-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to gstreamer0.10-pulseaudio-0.10.14-1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
