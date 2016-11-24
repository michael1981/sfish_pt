# This script was automatically generated from the SSA-2004-223-03
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18754);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-223-03 security update');
script_set_attribute(attribute:'description', value: '
New sox packages are available for Slackware 8.1, 9.0, 9.1, 10.0, and -current
to fix buffer overflow security issues that could allow a malicious WAV file
to execute arbitrary code.

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-223-03");
script_summary("SSA-2004-223-03 sox ");
script_name(english: "SSA-2004-223-03 sox ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "sox", pkgver: "12.17.4", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package sox is vulnerable in Slackware 8.1
Upgrade to sox-12.17.4-i386-3 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "sox", pkgver: "12.17.4", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package sox is vulnerable in Slackware 9.0
Upgrade to sox-12.17.4-i386-3 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "sox", pkgver: "12.17.4", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package sox is vulnerable in Slackware 9.1
Upgrade to sox-12.17.4-i486-3 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "sox", pkgver: "12.17.4", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package sox is vulnerable in Slackware 10.0
Upgrade to sox-12.17.4-i486-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "sox", pkgver: "12.17.4", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package sox is vulnerable in Slackware -current
Upgrade to sox-12.17.4-i486-3 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
