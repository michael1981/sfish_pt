# This script was automatically generated from the 786-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39363);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "786-1");
script_summary(english:"apr-util vulnerabilities");
script_name(english:"USN786-1 : apr-util vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libaprutil1 
- libaprutil1-dbg 
- libaprutil1-dev 
');
script_set_attribute(attribute:'description', value: 'Matthew Palmer discovered an underflow flaw in apr-util. An attacker could
cause a denial of service via application crash in Apache using a crafted
SVNMasterURI directive, .htaccess file, or when using mod_apreq2.
Applications using libapreq2 are also affected. (CVE-2009-0023)

It was discovered that the XML parser did not properly handle entity
expansion. A remote attacker could cause a denial of service via memory
resource consumption by sending a crafted request to an Apache server
configured to use mod_dav or mod_dav_svn. (CVE-2009-1955)

C. Michael Pilato discovered an off-by-one buffer overflow in apr-util when
formatting certain strings. For big-endian machines (powerpc, hppa and
sparc in Ubuntu), a remote attacker could cause a denial of service or
information disclosure leak. All other architectures for Ubuntu are
not considered to be at risk. (CVE-2009-1956)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libaprutil1-1.2.12+dfsg-8ubuntu0.1 (Ubuntu 9.04)
- libaprutil1-dbg-1.2.12+dfsg-8ubuntu0.1 (Ubuntu 9.04)
- libaprutil1-dev-1.2.12+dfsg-8ubuntu0.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2009-0023","CVE-2009-1955","CVE-2009-1956");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libaprutil1", pkgver: "1.2.12+dfsg-8ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libaprutil1-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libaprutil1-1.2.12+dfsg-8ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libaprutil1-dbg", pkgver: "1.2.12+dfsg-8ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libaprutil1-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libaprutil1-dbg-1.2.12+dfsg-8ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libaprutil1-dev", pkgver: "1.2.12+dfsg-8ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libaprutil1-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libaprutil1-dev-1.2.12+dfsg-8ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
