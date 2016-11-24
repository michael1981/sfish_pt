# This script was automatically generated from the SSA-2007-283-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(26972);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2007-283-01 security update');
script_set_attribute(attribute:'description', value: '
New glibc-zoneinfo packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, 10.2, 11.0, and 12.0 to update the timezone tables to the latest
versions.  If you\'ve noticed your clock has wandered off, these packages
should fix the problem.

This isn\'t really a "security issue" (or is a minor one), but it\'s an
important fix nevertheless.


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2007-283-01");
script_summary("SSA-2007-283-01 glibc-zoneinfo ");
script_name(english: "SSA-2007-283-01 glibc-zoneinfo ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "glibc-zoneinfo", pkgver: "2.2.5", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-zoneinfo is vulnerable in Slackware 8.1
Upgrade to glibc-zoneinfo-2.2.5-i386-4_slack8.1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "glibc-zoneinfo", pkgver: "2.3.1", pkgnum:  "6", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-zoneinfo is vulnerable in Slackware 9.0
Upgrade to glibc-zoneinfo-2.3.1-noarch-6_slack9.0 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "glibc-zoneinfo", pkgver: "2.3.2", pkgnum:  "3", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-zoneinfo is vulnerable in Slackware 9.1
Upgrade to glibc-zoneinfo-2.3.2-noarch-3_slack9.1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "glibc-zoneinfo", pkgver: "2.3.2", pkgnum:  "8", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-zoneinfo is vulnerable in Slackware 10.0
Upgrade to glibc-zoneinfo-2.3.2-noarch-8_slack10.0 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "glibc-zoneinfo", pkgver: "2.3.4", pkgnum:  "3", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-zoneinfo is vulnerable in Slackware 10.1
Upgrade to glibc-zoneinfo-2.3.4-noarch-3_slack10.1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "glibc-zoneinfo", pkgver: "2.3.5", pkgnum:  "8", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-zoneinfo is vulnerable in Slackware 10.2
Upgrade to glibc-zoneinfo-2.3.5-noarch-8_slack10.2 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "glibc-zoneinfo", pkgver: "2.3.6", pkgnum:  "8", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-zoneinfo is vulnerable in Slackware 11.0
Upgrade to glibc-zoneinfo-2.3.6-noarch-8_slack11.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "glibc-zoneinfo", pkgver: "2.5", pkgnum:  "5", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-zoneinfo is vulnerable in Slackware 12.0
Upgrade to glibc-zoneinfo-2.5-noarch-5_slack12.0 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
