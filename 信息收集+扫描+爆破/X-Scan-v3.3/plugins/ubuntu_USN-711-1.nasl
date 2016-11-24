# This script was automatically generated from the 711-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37842);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "711-1");
script_summary(english:"ktorrent vulnerabilities");
script_name(english:"USN711-1 : ktorrent vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ktorrent 
- ktorrent-dbg 
');
script_set_attribute(attribute:'description', value: 'It was discovered that KTorrent did not properly restrict access when using the
web interface plugin. A remote attacker could use a crafted http request and
upload arbitrary torrent files to trigger the start of downloads and seeding.
(CVE-2008-5905)

It was discovered that KTorrent did not properly handle certain parameters when
using the web interface plugin. A remote attacker could use crafted http
requests to execute arbitrary PHP code. (CVE-2008-5906)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ktorrent-3.1.2+dfsg.1-0ubuntu2.1 (Ubuntu 8.10)
- ktorrent-dbg-3.1.2+dfsg.1-0ubuntu2.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-5905","CVE-2008-5906");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "ktorrent", pkgver: "3.1.2+dfsg.1-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ktorrent-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ktorrent-3.1.2+dfsg.1-0ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ktorrent-dbg", pkgver: "3.1.2+dfsg.1-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ktorrent-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ktorrent-dbg-3.1.2+dfsg.1-0ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
