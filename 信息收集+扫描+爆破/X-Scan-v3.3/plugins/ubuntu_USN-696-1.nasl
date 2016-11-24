# This script was automatically generated from the 696-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36657);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "696-1");
script_summary(english:"avahi vulnerabilities");
script_name(english:"USN696-1 : avahi vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avahi-autoipd 
- avahi-daemon 
- avahi-dbg 
- avahi-discover 
- avahi-dnsconfd 
- avahi-ui-utils 
- avahi-utils 
- libavahi-cil 
- libavahi-client-dev 
- libavahi-client3 
- libavahi-common-data 
- libavahi-common-dev 
- libavahi-common3 
- libavahi-compat-howl-dev 
- libavahi-compat-howl0 
- libavahi-compat-libdnssd-dev 
- libavahi-compat-libdnssd1 
- libavahi-core-dev 
- libavahi-core4 
- libavahi-core5 
- libavahi-glib-dev 
- libavahi-glib1 
- libav
[...]');
script_set_attribute(attribute:'description', value: 'Emanuele Aina discovered that Avahi did not properly validate it\'s input when
processing data over D-Bus. A local attacker could send an empty TXT message
via D-Bus and cause a denial of service (failed assertion). This issue only
affected Ubuntu 6.06 LTS. (CVE-2007-3372)

Hugo Dias discovered that Avahi did not properly verify it\'s input when
processing mDNS packets. A remote attacker could send a crafted mDNS packet
and cause a denial of service (assertion failure). (CVE-2008-5081)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avahi-autoipd-0.6.23-2ubuntu2.1 (Ubuntu 8.10)
- avahi-daemon-0.6.23-2ubuntu2.1 (Ubuntu 8.10)
- avahi-dbg-0.6.23-2ubuntu2.1 (Ubuntu 8.10)
- avahi-discover-0.6.23-2ubuntu2.1 (Ubuntu 8.10)
- avahi-dnsconfd-0.6.23-2ubuntu2.1 (Ubuntu 8.10)
- avahi-ui-utils-0.6.23-2ubuntu2.1 (Ubuntu 8.10)
- avahi-utils-0.6.23-2ubuntu2.1 (Ubuntu 8.10)
- libavahi-cil-0.6.10-0ubuntu3.5 (Ubuntu 6.06)
- libavahi-client-dev-0.6.23-2ubuntu2.1 (Ubuntu 8.10)
- libavahi-client3-0.6.23-2ubuntu2.1 (Ubuntu 8.10)
- libavahi-co
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-3372","CVE-2008-5081");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "avahi-autoipd", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-autoipd-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to avahi-autoipd-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "avahi-daemon", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-daemon-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to avahi-daemon-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "avahi-dbg", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to avahi-dbg-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "avahi-discover", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-discover-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to avahi-discover-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "avahi-dnsconfd", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-dnsconfd-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to avahi-dnsconfd-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "avahi-ui-utils", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-ui-utils-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to avahi-ui-utils-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "avahi-utils", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-utils-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to avahi-utils-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libavahi-cil", pkgver: "0.6.10-0ubuntu3.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-cil-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libavahi-cil-0.6.10-0ubuntu3.5
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-client-dev", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-client-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-client-dev-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-client3", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-client3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-client3-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-common-data", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-common-data-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-common-data-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-common-dev", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-common-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-common-dev-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-common3", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-common3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-common3-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-compat-howl-dev", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-compat-howl-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-compat-howl-dev-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-compat-howl0", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-compat-howl0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-compat-howl0-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-compat-libdnssd-dev", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-compat-libdnssd-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-compat-libdnssd-dev-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-compat-libdnssd1", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-compat-libdnssd1-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-compat-libdnssd1-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-core-dev", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-core-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-core-dev-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libavahi-core4", pkgver: "0.6.10-0ubuntu3.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-core4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libavahi-core4-0.6.10-0ubuntu3.5
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-core5", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-core5-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-core5-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-glib-dev", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-glib-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-glib-dev-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-glib1", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-glib1-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-glib1-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-gobject-dev", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-gobject-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-gobject-dev-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-gobject0", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-gobject0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-gobject0-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-qt3-1", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-qt3-1-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-qt3-1-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-qt3-dev", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-qt3-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-qt3-dev-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-qt4-1", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-qt4-1-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-qt4-1-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-qt4-dev", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-qt4-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-qt4-dev-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-ui-dev", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-ui-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-ui-dev-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavahi-ui0", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-ui0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavahi-ui0-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "monodoc-avahi-manual", pkgver: "0.6.10-0ubuntu3.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package monodoc-avahi-manual-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to monodoc-avahi-manual-0.6.10-0ubuntu3.5
');
}
found = ubuntu_check(osver: "8.10", pkgname: "python-avahi", pkgver: "0.6.23-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-avahi-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-avahi-0.6.23-2ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-avahi", pkgver: "0.6.10-0ubuntu3.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-avahi-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-avahi-0.6.10-0ubuntu3.5
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
