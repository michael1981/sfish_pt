# This script was automatically generated from the SSA-2003-273-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18740);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2003-273-01 security update');
script_set_attribute(attribute:'description', value: '
Upgraded OpenSSL packages are available for Slackware 8.1, 9.0,
9.1, and -current.  These fix problems with ASN.1 parsing which
could lead to a denial of service.  It is not known whether the
problems could lead to the running of malicious code on the
server, but it has not been ruled out.

We recommend sites that use OpenSSL upgrade to the fixed packages
right away.


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2003-273-01");
script_summary("SSA-2003-273-01 OpenSSL security update ");
script_name(english: "SSA-2003-273-01 OpenSSL security update ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "openssl", pkgver: "0.9.6k", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssl is vulnerable in Slackware 8.1
Upgrade to openssl-0.9.6k-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "openssl-solibs", pkgver: "0.9.6k", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssl-solibs is vulnerable in Slackware 8.1
Upgrade to openssl-solibs-0.9.6k-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "openssl", pkgver: "0.9.7c", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssl is vulnerable in Slackware 9.0
Upgrade to openssl-0.9.7c-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "openssl-solibs", pkgver: "0.9.7c", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssl-solibs is vulnerable in Slackware 9.0
Upgrade to openssl-solibs-0.9.7c-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "openssl", pkgver: "0.9.7c", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssl is vulnerable in Slackware 9.1
Upgrade to openssl-0.9.7c-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "openssl-solibs", pkgver: "0.9.7c", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssl-solibs is vulnerable in Slackware 9.1
Upgrade to openssl-solibs-0.9.7c-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "openssl-solibs", pkgver: "0.9.7c", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssl-solibs is vulnerable in Slackware -current
Upgrade to openssl-solibs-0.9.7c-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "openssl", pkgver: "0.9.7c", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package openssl is vulnerable in Slackware -current
Upgrade to openssl-0.9.7c-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
