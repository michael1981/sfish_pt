# This script was automatically generated from the 88-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20713);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "88-1");
script_summary(english:"reportbug information disclosure");
script_name(english:"USN88-1 : reportbug information disclosure");
script_set_attribute(attribute:'synopsis', value: 'The remote package "reportbug" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Rolf Leggewie discovered two information disclosure bugs in reportbug.

The per-user configuration file ~/.reportbugrc was created
world-readable. If it contained email smarthost passwords, these were
readable by any other user on the computer storing the home directory.

reportbug usually includes the settings from ~/.reportbugrc in
generated bug reports. This included the "smtppasswd" setting (the
password for an SMTP email smarthost) as well. The password is
now hidden from reports.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- reportbug-2.62ubuntu1.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "reportbug", pkgver: "2.62ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package reportbug-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to reportbug-2.62ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
