# This script was automatically generated from the 698-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37968);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "698-3");
script_summary(english:"nagios2 vulnerabilities");
script_name(english:"USN698-3 : nagios2 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- nagios2 
- nagios2-common 
- nagios2-dbg 
- nagios2-doc 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Nagios was vulnerable to a Cross-site request forgery
(CSRF) vulnerability. If an authenticated nagios user were tricked into
clicking a link on a specially crafted web page, an attacker could trigger
commands to be processed by Nagios and execute arbitrary programs. This
update alters Nagios behaviour by disabling submission of CMD_CHANGE commands.
(CVE-2008-5028)

It was discovered that Nagios did not properly parse commands submitted using
the web interface. An authenticated user could use a custom form or a browser
addon to bypass security restrictions and submit unauthorized commands.
(CVE-2008-5027)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- nagios2-2.11-1ubuntu1.4 (Ubuntu 8.04)
- nagios2-common-2.11-1ubuntu1.4 (Ubuntu 8.04)
- nagios2-dbg-2.11-1ubuntu1.4 (Ubuntu 8.04)
- nagios2-doc-2.11-1ubuntu1.4 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-5027","CVE-2008-5028");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "nagios2", pkgver: "2.11-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nagios2-2.11-1ubuntu1.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nagios2-common", pkgver: "2.11-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios2-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nagios2-common-2.11-1ubuntu1.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nagios2-dbg", pkgver: "2.11-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios2-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nagios2-dbg-2.11-1ubuntu1.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nagios2-doc", pkgver: "2.11-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios2-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nagios2-doc-2.11-1ubuntu1.4
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
