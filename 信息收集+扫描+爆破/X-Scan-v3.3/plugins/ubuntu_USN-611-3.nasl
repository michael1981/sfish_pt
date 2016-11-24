# This script was automatically generated from the 611-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32193);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "611-3");
script_summary(english:"GStreamer Good Plugins vulnerability");
script_name(english:"USN611-3 : GStreamer Good Plugins vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gstreamer0.10-esd 
- gstreamer0.10-plugins-good 
- gstreamer0.10-plugins-good-dbg 
- gstreamer0.10-plugins-good-doc 
');
script_set_attribute(attribute:'description', value: 'USN-611-1 fixed a vulnerability in Speex. This update provides the
corresponding update for GStreamer Good Plugins.

Original advisory details:

 It was discovered that Speex did not properly validate its input when
 processing Speex file headers. If a user or automated system were
 tricked into opening a specially crafted Speex file, an attacker could
 create a denial of service in applications linked against Speex or
 possibly execute arbitrary code as the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gstreamer0.10-esd-0.10.7-3ubuntu0.1 (Ubuntu 8.04)
- gstreamer0.10-plugins-good-0.10.7-3ubuntu0.1 (Ubuntu 8.04)
- gstreamer0.10-plugins-good-dbg-0.10.7-3ubuntu0.1 (Ubuntu 8.04)
- gstreamer0.10-plugins-good-doc-0.10.7-3ubuntu0.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1686");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "gstreamer0.10-esd", pkgver: "0.10.7-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-esd-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to gstreamer0.10-esd-0.10.7-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "gstreamer0.10-plugins-good", pkgver: "0.10.7-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-plugins-good-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to gstreamer0.10-plugins-good-0.10.7-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "gstreamer0.10-plugins-good-dbg", pkgver: "0.10.7-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-plugins-good-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to gstreamer0.10-plugins-good-dbg-0.10.7-3ubuntu0.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "gstreamer0.10-plugins-good-doc", pkgver: "0.10.7-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gstreamer0.10-plugins-good-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to gstreamer0.10-plugins-good-doc-0.10.7-3ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
