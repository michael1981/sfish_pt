# This script was automatically generated from the 278-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21372);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "278-1");
script_summary(english:"gdm vulnerabilitiy");
script_name(english:"USN278-1 : gdm vulnerabilitiy");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gdm" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Marcus Meissner discovered a race condition in gdm\'s handling of the
~/.ICEauthority file permissions. A local attacker could exploit this
to become the owner of an arbitrary file in the system. When getting
control over automatically executed scripts (like cron jobs), the
attacker could eventually leverage this flaw to execute arbitrary
commands with root privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gdm-2.8.0.5-0ubuntu1.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-1057");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "gdm", pkgver: "2.8.0.5-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gdm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gdm-2.8.0.5-0ubuntu1.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
