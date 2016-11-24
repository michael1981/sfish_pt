# This script was automatically generated from the 735-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37364);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "735-1");
script_summary(english:"gst-plugins-base0.10 vulnerability");
script_name(english:"USN735-1 : gst-plugins-base0.10 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gstreamer0.10-alsa 
- gstreamer0.10-gnomevfs 
- gstreamer0.10-plugins-base 
- gstreamer0.10-plugins-base-apps 
- gstreamer0.10-plugins-base-dbg 
- gstreamer0.10-plugins-base-doc 
- gstreamer0.10-x 
- libgstreamer-plugins-base0.10-0 
- libgstreamer-plugins-base0.10-dev 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the Base64 decoding functions in GStreamer Base
Plugins did not properly handle large images in Vorbis file tags. If a user
were tricked into opening a specially crafted Vorbis file, an attacker
could possibly execute arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gstreamer0.10-alsa-0.10.21-3ubuntu0.1 (Ubuntu 8.10)
- gstreamer0.10-gnomevfs-0.10.21-3ubuntu0.1 (Ubuntu 8.10)
- gstreamer0.10-plugins-base-0.10.21-3ubuntu0.1 (Ubuntu 8.10)
- gstreamer0.10-plugins-base-apps-0.10.21-3ubuntu0.1 (Ubuntu 8.10)
- gstreamer0.10-plugins-base-dbg-0.10.21-3ubuntu0.1 (Ubuntu 8.10)
- gstreamer0.10-plugins-base-doc-0.10.21-3ubuntu0.1 (Ubuntu 8.10)
- gstreamer0.10-x-0.10.21-3ubuntu0.1 (Ubuntu 8.10)
- libgstreamer-plugins-base0.10-0-0.10.21-3ubuntu0.1 (Ubuntu 8.10)
- libg
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-0586");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "gstreamer0.10-alsa", pkgver: "0.10.21-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-alsa-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gstreamer0.10-alsa-0.10.21-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gstreamer0.10-gnomevfs", pkgver: "0.10.21-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-gnomevfs-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gstreamer0.10-gnomevfs-0.10.21-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gstreamer0.10-plugins-base", pkgver: "0.10.21-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-plugins-base-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gstreamer0.10-plugins-base-0.10.21-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gstreamer0.10-plugins-base-apps", pkgver: "0.10.21-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-plugins-base-apps-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gstreamer0.10-plugins-base-apps-0.10.21-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gstreamer0.10-plugins-base-dbg", pkgver: "0.10.21-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-plugins-base-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gstreamer0.10-plugins-base-dbg-0.10.21-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gstreamer0.10-plugins-base-doc", pkgver: "0.10.21-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-plugins-base-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gstreamer0.10-plugins-base-doc-0.10.21-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gstreamer0.10-x", pkgver: "0.10.21-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-x-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gstreamer0.10-x-0.10.21-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgstreamer-plugins-base0.10-0", pkgver: "0.10.21-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgstreamer-plugins-base0.10-0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgstreamer-plugins-base0.10-0-0.10.21-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgstreamer-plugins-base0.10-dev", pkgver: "0.10.21-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgstreamer-plugins-base0.10-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgstreamer-plugins-base0.10-dev-0.10.21-3ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
