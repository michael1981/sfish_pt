# This script was automatically generated from the 778-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38984);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "778-1");
script_summary(english:"cron vulnerability");
script_name(english:"USN778-1 : cron vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "cron" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'It was discovered that cron did not properly check the return code of
the setgid() and initgroups() system calls. A local attacker could use
this to escalate group privileges. Please note that cron versions 3.0pl1-64
and later were already patched to address the more serious setuid() check
referred to by CVE-2006-2607.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- cron-3.0pl1-105ubuntu1.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2607");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "cron", pkgver: "3.0pl1-105ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cron-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cron-3.0pl1-105ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
