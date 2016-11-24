# This script was automatically generated from the 795-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39601);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "795-1");
script_summary(english:"nagios2, nagios3 vulnerability");
script_name(english:"USN795-1 : nagios2, nagios3 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- nagios2 
- nagios2-common 
- nagios2-dbg 
- nagios2-doc 
- nagios3 
- nagios3-common 
- nagios3-dbg 
- nagios3-doc 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Nagios did not properly parse certain commands
submitted using the WAP web interface. An authenticated user could exploit
this flaw and execute arbitrary programs on the server.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- nagios2-2.11-1ubuntu1.5 (Ubuntu 8.04)
- nagios2-common-2.11-1ubuntu1.5 (Ubuntu 8.04)
- nagios2-dbg-2.11-1ubuntu1.5 (Ubuntu 8.04)
- nagios2-doc-2.11-1ubuntu1.5 (Ubuntu 8.04)
- nagios3-3.0.6-2ubuntu1.1 (Ubuntu 9.04)
- nagios3-common-3.0.6-2ubuntu1.1 (Ubuntu 9.04)
- nagios3-dbg-3.0.6-2ubuntu1.1 (Ubuntu 9.04)
- nagios3-doc-3.0.6-2ubuntu1.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-2288");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "nagios2", pkgver: "2.11-1ubuntu1.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nagios2-2.11-1ubuntu1.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nagios2-common", pkgver: "2.11-1ubuntu1.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios2-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nagios2-common-2.11-1ubuntu1.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nagios2-dbg", pkgver: "2.11-1ubuntu1.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios2-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nagios2-dbg-2.11-1ubuntu1.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nagios2-doc", pkgver: "2.11-1ubuntu1.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios2-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nagios2-doc-2.11-1ubuntu1.5
');
}
found = ubuntu_check(osver: "9.04", pkgname: "nagios3", pkgver: "3.0.6-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to nagios3-3.0.6-2ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "nagios3-common", pkgver: "3.0.6-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios3-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to nagios3-common-3.0.6-2ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "nagios3-dbg", pkgver: "3.0.6-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios3-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to nagios3-dbg-3.0.6-2ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "nagios3-doc", pkgver: "3.0.6-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nagios3-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to nagios3-doc-3.0.6-2ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
