# This script was automatically generated from the 698-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36674);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "698-1");
script_summary(english:"nagios vulnerability");
script_name(english:"USN698-1 : nagios vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- nagios-common 
- nagios-mysql 
- nagios-pgsql 
- nagios-text 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Nagios did not properly parse commands submitted using
the web interface. An authenticated user could use a custom form or a browser
addon to bypass security restrictions and submit unauthorized commands.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- nagios-common-1.3-cvs.20050402-8ubuntu8 (Ubuntu 6.06)
- nagios-mysql-1.3-cvs.20050402-8ubuntu8 (Ubuntu 6.06)
- nagios-pgsql-1.3-cvs.20050402-8ubuntu8 (Ubuntu 6.06)
- nagios-text-1.3-cvs.20050402-8ubuntu8 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-5027");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "nagios-common", pkgver: "1.3-cvs.20050402-8ubuntu8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nagios-common-1.3-cvs.20050402-8ubuntu8
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nagios-mysql", pkgver: "1.3-cvs.20050402-8ubuntu8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-mysql-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nagios-mysql-1.3-cvs.20050402-8ubuntu8
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nagios-pgsql", pkgver: "1.3-cvs.20050402-8ubuntu8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-pgsql-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nagios-pgsql-1.3-cvs.20050402-8ubuntu8
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nagios-text", pkgver: "1.3-cvs.20050402-8ubuntu8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios-text-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nagios-text-1.3-cvs.20050402-8ubuntu8
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
