# This script was automatically generated from the 287-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21612);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "287-1");
script_summary(english:"nagios vulnerability");
script_name(english:"USN287-1 : nagios vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- nagios-common 
- nagios-mysql 
- nagios-pgsql 
- nagios-text 
');
script_set_attribute(attribute:'description', value: 'The nagios CGI scripts did not sufficiently check the validity of the
HTTP Content-Length attribute. By sending a specially crafted HTTP
request with an invalidly large Content-Length value to the Nagios
server, a remote attacker could exploit this to execute arbitrary code
with web server privileges.

Please note that the Apache 2 web server already checks for valid
Content-Length values, so installations using Apache 2 (the only web
server officially supported in Ubuntu) are not vulnerable to this
flaw.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- nagios-common-1.3-cvs.20050402-4ubuntu3.2 (Ubuntu 5.10)
- nagios-mysql-1.3-cvs.20050402-4ubuntu3.2 (Ubuntu 5.10)
- nagios-pgsql-1.3-cvs.20050402-4ubuntu3.2 (Ubuntu 5.10)
- nagios-text-1.3-cvs.20050402-4ubuntu3.2 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2489");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "nagios-common", pkgver: "1.3-cvs.20050402-4ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to nagios-common-1.3-cvs.20050402-4ubuntu3.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "nagios-mysql", pkgver: "1.3-cvs.20050402-4ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-mysql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to nagios-mysql-1.3-cvs.20050402-4ubuntu3.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "nagios-pgsql", pkgver: "1.3-cvs.20050402-4ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-pgsql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to nagios-pgsql-1.3-cvs.20050402-4ubuntu3.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "nagios-text", pkgver: "1.3-cvs.20050402-4ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-text-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to nagios-text-1.3-cvs.20050402-4ubuntu3.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
