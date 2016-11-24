# This script was automatically generated from the 674-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37887);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "674-1");
script_summary(english:"hplip vulnerabilities");
script_name(english:"USN674-1 : hplip vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- hpijs 
- hpijs-ppds 
- hplip 
- hplip-data 
- hplip-dbg 
- hplip-doc 
- hplip-gui 
- hplip-ppds 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the hpssd tool of hplip did not validate
privileges in the alert-mailing function. A local attacker could
exploit this to gain privileges and send e-mail messages from the
account of the hplip user. This update alters hplip behaviour by
preventing users from setting alerts and by moving alert configuration
to a root-controlled /etc/hp/alerts.conf file. (CVE-2008-2940)

It was discovered that the hpssd tool of hplip did not correctly
handle certain commands. A local attacker could use a specially
crafted packet to crash hpssd, leading to a denial of service.
(CVE-2008-2941)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- hpijs-2.8.2+2.8.2-0ubuntu8.1 (Ubuntu 8.04)
- hpijs-ppds-2.8.2+2.8.2-0ubuntu8.1 (Ubuntu 8.04)
- hplip-2.8.2-0ubuntu8.1 (Ubuntu 8.04)
- hplip-data-2.8.2-0ubuntu8.1 (Ubuntu 8.04)
- hplip-dbg-2.8.2-0ubuntu8.1 (Ubuntu 8.04)
- hplip-doc-2.8.2-0ubuntu8.1 (Ubuntu 8.04)
- hplip-gui-2.8.2-0ubuntu8.1 (Ubuntu 8.04)
- hplip-ppds-0.9.7-4ubuntu1.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-2940","CVE-2008-2941");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "hpijs", pkgver: "2.8.2+2.8.2-0ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hpijs-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to hpijs-2.8.2+2.8.2-0ubuntu8.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "hpijs-ppds", pkgver: "2.8.2+2.8.2-0ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hpijs-ppds-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to hpijs-ppds-2.8.2+2.8.2-0ubuntu8.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "hplip", pkgver: "2.8.2-0ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to hplip-2.8.2-0ubuntu8.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "hplip-data", pkgver: "2.8.2-0ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-data-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to hplip-data-2.8.2-0ubuntu8.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "hplip-dbg", pkgver: "2.8.2-0ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to hplip-dbg-2.8.2-0ubuntu8.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "hplip-doc", pkgver: "2.8.2-0ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to hplip-doc-2.8.2-0ubuntu8.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "hplip-gui", pkgver: "2.8.2-0ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-gui-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to hplip-gui-2.8.2-0ubuntu8.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "hplip-ppds", pkgver: "0.9.7-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-ppds-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to hplip-ppds-0.9.7-4ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
