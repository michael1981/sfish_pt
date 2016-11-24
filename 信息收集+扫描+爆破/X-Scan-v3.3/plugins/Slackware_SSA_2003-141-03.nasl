# This script was automatically generated from the SSA-2003-141-03
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37391);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2003-141-03 security update');
script_set_attribute(attribute:'description', value: '
An integer overflow in the xdrmem_getbytes() function found in the glibc
library has been fixed.  This could allow a remote attacker to execute
arbitrary code by exploiting RPC service that use xdrmem_getbytes().  None of
the default RPC services provided by Slackware  appear to use this function,
but third-party applications may make use of it.

We recommend upgrading to these new glibc packages.


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2003-141-03");
script_summary("SSA-2003-141-03 glibc XDR overflow fix ");
script_name(english: "SSA-2003-141-03 glibc XDR overflow fix ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "glibc", pkgver: "2.2.5", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc is vulnerable in Slackware 8.1
Upgrade to glibc-2.2.5-i386-4 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "glibc-solibs", pkgver: "2.2.5", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-solibs is vulnerable in Slackware 8.1
Upgrade to glibc-solibs-2.2.5-i386-4 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "glibc", pkgver: "2.3.1", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc is vulnerable in Slackware 9.0
Upgrade to glibc-2.3.1-i386-4 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "glibc-debug", pkgver: "2.3.1", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-debug is vulnerable in Slackware 9.0
Upgrade to glibc-debug-2.3.1-i386-4 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "glibc-i18n", pkgver: "2.3.1", pkgnum:  "4", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-i18n is vulnerable in Slackware 9.0
Upgrade to glibc-i18n-2.3.1-noarch-4 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "glibc-profile", pkgver: "2.3.1", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-profile is vulnerable in Slackware 9.0
Upgrade to glibc-profile-2.3.1-i386-4 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "glibc-solibs", pkgver: "2.3.1", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-solibs is vulnerable in Slackware 9.0
Upgrade to glibc-solibs-2.3.1-i386-4 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "glibc-zoneinfo", pkgver: "2.3.1", pkgnum:  "4", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package glibc-zoneinfo is vulnerable in Slackware 9.0
Upgrade to glibc-zoneinfo-2.3.1-noarch-4 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
