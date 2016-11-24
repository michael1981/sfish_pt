# This script was automatically generated from the 379-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27961);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "379-1");
script_summary(english:"texinfo vulnerability");
script_name(english:"USN379-1 : texinfo vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- info 
- texinfo 
');
script_set_attribute(attribute:'description', value: 'Miloslav Trmac discovered a buffer overflow in texinfo\'s index 
processor.  If a user is tricked into processing a .texi file with 
texindex, this could lead to arbitrary code execution with user 
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- info-4.8.dfsg.1-1ubuntu0.1 (Ubuntu 6.10)
- texinfo-4.8.dfsg.1-1ubuntu0.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4810");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "info", pkgver: "4.8.dfsg.1-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package info-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to info-4.8.dfsg.1-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "texinfo", pkgver: "4.8.dfsg.1-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package texinfo-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to texinfo-4.8.dfsg.1-1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
