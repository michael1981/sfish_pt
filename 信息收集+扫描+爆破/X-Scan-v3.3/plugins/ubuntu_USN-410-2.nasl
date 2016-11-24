# This script was automatically generated from the 410-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27999);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "410-2");
script_summary(english:"teTeX vulnerability");
script_name(english:"USN410-2 : teTeX vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libkpathsea-dev 
- libkpathsea3 
- tetex-bin 
');
script_set_attribute(attribute:'description', value: 'USN-410-1 fixed vulnerabilities in the poppler PDF loader library.  This 
update provides the corresponding updates for a copy of this code in 
tetex-bin in Ubuntu 5.10.  Versions of tetex-bin after Ubuntu 5.10 use 
poppler directly and do not need a separate update.

Original advisory details:

 The poppler PDF loader library did not limit the recursion depth of
 the page model tree. By tricking a user into opening a specially
 crafter PDF file, this could be exploited to trigger an infinite loop
 and eventually crash an application that uses this library.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libkpathsea-dev-2.0.2-30ubuntu3.6 (Ubuntu 5.10)
- libkpathsea3-2.0.2-30ubuntu3.6 (Ubuntu 5.10)
- tetex-bin-2.0.2-30ubuntu3.6 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-0104");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libkpathsea-dev", pkgver: "2.0.2-30ubuntu3.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkpathsea-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkpathsea-dev-2.0.2-30ubuntu3.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libkpathsea3", pkgver: "2.0.2-30ubuntu3.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkpathsea3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libkpathsea3-2.0.2-30ubuntu3.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "tetex-bin", pkgver: "2.0.2-30ubuntu3.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tetex-bin-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to tetex-bin-2.0.2-30ubuntu3.6
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
