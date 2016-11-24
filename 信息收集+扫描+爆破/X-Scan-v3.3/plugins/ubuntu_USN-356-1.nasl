# This script was automatically generated from the 356-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27936);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "356-1");
script_summary(english:"gdb vulnerability");
script_name(english:"USN356-1 : gdb vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gdb" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Will Drewry, of the Google Security Team, discovered buffer overflows
in GDB\'s DWARF processing.  This would allow an attacker to execute
arbitrary code with user privileges by tricking the user into using
GDB to load an executable that contained malicious debugging
information.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gdb-6.4-1ubuntu5.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4146");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "gdb", pkgver: "6.4-1ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gdb-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gdb-6.4-1ubuntu5.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
