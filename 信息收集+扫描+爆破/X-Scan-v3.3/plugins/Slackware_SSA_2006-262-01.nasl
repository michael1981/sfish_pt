# This script was automatically generated from the SSA-2006-262-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(22421);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2006-262-01 security update');
script_set_attribute(attribute:'description', value: '
New gzip packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1, 10.2,
and -current to fix possible security issues.

More details about the issues fixed may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0758
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0988
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1228
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4334
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4335
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4336
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4337
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4338


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2006-262-01");
script_summary("SSA-2006-262-01 gzip ");
script_name(english: "SSA-2006-262-01 gzip ");
script_cve_id("CVE-2005-0758","CVE-2005-0988","CVE-2005-1228","CVE-2006-4334","CVE-2006-4335","CVE-2006-4336","CVE-2006-4337","CVE-2006-4338");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "gzip", pkgver: "1.3.5", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gzip is vulnerable in Slackware 8.1
Upgrade to gzip-1.3.5-i386-1_slack8.1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "gzip", pkgver: "1.3.5", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gzip is vulnerable in Slackware 9.0
Upgrade to gzip-1.3.5-i386-1_slack9.0 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "gzip", pkgver: "1.3.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gzip is vulnerable in Slackware 9.1
Upgrade to gzip-1.3.5-i486-1_slack9.1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "gzip", pkgver: "1.3.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gzip is vulnerable in Slackware 10.0
Upgrade to gzip-1.3.5-i486-1_slack10.0 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "gzip", pkgver: "1.3.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gzip is vulnerable in Slackware 10.1
Upgrade to gzip-1.3.5-i486-1_slack10.1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "gzip", pkgver: "1.3.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gzip is vulnerable in Slackware 10.2
Upgrade to gzip-1.3.5-i486-1_slack10.2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "gzip", pkgver: "1.3.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package gzip is vulnerable in Slackware -current
Upgrade to gzip-1.3.5-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
