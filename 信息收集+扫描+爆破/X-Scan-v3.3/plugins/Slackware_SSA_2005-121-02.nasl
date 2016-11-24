# This script was automatically generated from the SSA-2005-121-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18809);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2005-121-02 security update');
script_set_attribute(attribute:'description', value: '
New xine-lib packages are available for Slackware 10.0, 10.1, and -current to
fix security issues.  The xine frontends have also been upgraded.

For more details on the xine-lib security issues, see:
  http://xinehq.de/index.php/security/XSA-2004-8


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2005-121-02");
script_summary("SSA-2005-121-02 xine-lib ");
script_name(english: "SSA-2005-121-02 xine-lib ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "10.0", pkgname: "gxine", pkgver: "0.4.4", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gxine is vulnerable in Slackware 10.0
Upgrade to gxine-0.4.4-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "xine-lib", pkgver: "1.0.1", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xine-lib is vulnerable in Slackware 10.0
Upgrade to xine-lib-1.0.1-i686-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "xine-ui", pkgver: "0.99.3", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xine-ui is vulnerable in Slackware 10.0
Upgrade to xine-ui-0.99.3-i686-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "gxine", pkgver: "0.4.4", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gxine is vulnerable in Slackware 10.1
Upgrade to gxine-0.4.4-i486-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "xine-lib", pkgver: "1.0.1", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xine-lib is vulnerable in Slackware 10.1
Upgrade to xine-lib-1.0.1-i686-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "gxine", pkgver: "0.4.4", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gxine is vulnerable in Slackware -current
Upgrade to gxine-0.4.4-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "xine-lib", pkgver: "1.0.1", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xine-lib is vulnerable in Slackware -current
Upgrade to xine-lib-1.0.1-i686-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
