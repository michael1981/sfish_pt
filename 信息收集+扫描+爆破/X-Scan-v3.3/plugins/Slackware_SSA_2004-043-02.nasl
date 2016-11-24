# This script was automatically generated from the SSA-2004-043-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18771);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-043-02 security update');
script_set_attribute(attribute:'description', value: '
New XFree86 base packages are available for Slackware 8.1, 9.0,
9.1, and -current.  These fix overflows which could possibly be
exploited to gain unauthorized root access.  All sites running
XFree86 should upgrade to the new package.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0083
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0084
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0106


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-043-02");
script_summary("SSA-2004-043-02 XFree86 security update ");
script_name(english: "SSA-2004-043-02 XFree86 security update ");
script_cve_id("CVE-2004-0083","CVE-2004-0084","CVE-2004-0106");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "8.1", pkgname: "xfree86", pkgver: "4.2.1", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xfree86 is vulnerable in Slackware 8.1
Upgrade to xfree86-4.2.1-i386-3 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "xfree86", pkgver: "4.3.0", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xfree86 is vulnerable in Slackware 9.0
Upgrade to xfree86-4.3.0-i386-3 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "xfree86", pkgver: "4.3.0", pkgnum:  "6", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xfree86 is vulnerable in Slackware 9.1
Upgrade to xfree86-4.3.0-i486-6 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "xfree86", pkgver: "4.3.0", pkgnum:  "6", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xfree86 is vulnerable in Slackware -current
Upgrade to xfree86-4.3.0-i486-6 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
