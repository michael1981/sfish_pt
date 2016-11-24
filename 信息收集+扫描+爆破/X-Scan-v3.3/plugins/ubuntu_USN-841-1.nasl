# This script was automatically generated from the 841-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42043);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "841-1");
script_summary(english:"glib2.0 vulnerability");
script_name(english:"USN841-1 : glib2.0 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libgio-fam 
- libglib2.0-0 
- libglib2.0-0-dbg 
- libglib2.0-data 
- libglib2.0-dev 
- libglib2.0-doc 
');
script_set_attribute(attribute:'description', value: 'Arand Nash discovered that applications linked to GLib (e.g. Nautilus)
did not correctly copy symlinks.  If a user copied symlinks with GLib,
the symlink target files would become world-writable, allowing local
attackers to gain access to potentially sensitive information.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libgio-fam-2.20.1-0ubuntu2.1 (Ubuntu 9.04)
- libglib2.0-0-2.20.1-0ubuntu2.1 (Ubuntu 9.04)
- libglib2.0-0-dbg-2.20.1-0ubuntu2.1 (Ubuntu 9.04)
- libglib2.0-data-2.20.1-0ubuntu2.1 (Ubuntu 9.04)
- libglib2.0-dev-2.20.1-0ubuntu2.1 (Ubuntu 9.04)
- libglib2.0-doc-2.20.1-0ubuntu2.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-3289");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libgio-fam", pkgver: "2.20.1-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgio-fam-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libgio-fam-2.20.1-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libglib2.0-0", pkgver: "2.20.1-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libglib2.0-0-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libglib2.0-0-2.20.1-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libglib2.0-0-dbg", pkgver: "2.20.1-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libglib2.0-0-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libglib2.0-0-dbg-2.20.1-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libglib2.0-data", pkgver: "2.20.1-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libglib2.0-data-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libglib2.0-data-2.20.1-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libglib2.0-dev", pkgver: "2.20.1-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libglib2.0-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libglib2.0-dev-2.20.1-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libglib2.0-doc", pkgver: "2.20.1-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libglib2.0-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libglib2.0-doc-2.20.1-0ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
