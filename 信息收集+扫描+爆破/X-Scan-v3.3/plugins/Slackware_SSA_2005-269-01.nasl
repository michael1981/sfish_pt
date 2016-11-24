# This script was automatically generated from the SSA-2005-269-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(19866);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2005-269-01 security update');
script_set_attribute(attribute:'description', value: '
New Mozilla and Firefox packages are available for Slackware 10.0, 10.1,
10.2, and -current to fix security issues:

   MFSA 2005-59 Command-line handling on Linux allows shell execution
   MFSA 2005-58 Firefox 1.0.7 / Mozilla Suite 1.7.12 Vulnerability Fixes
   MFSA 2005-57 IDN heap overrun using soft-hyphens

More details about these issues may be found on the Mozilla web site:

  http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla
  http://www.mozilla.org/projects/security/known-vulnerabilities.html#Firefox


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2005-269-01");
script_summary("SSA-2005-269-01 Mozilla/Firefox ");
script_name(english: "SSA-2005-269-01 Mozilla/Firefox ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "10.0", pkgname: "mozilla", pkgver: "1.7.12", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware 10.0
Upgrade to mozilla-1.7.12-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "mozilla-plugins", pkgver: "1.7.12", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-plugins is vulnerable in Slackware 10.0
Upgrade to mozilla-plugins-1.7.12-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "mozilla", pkgver: "1.7.12", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware 10.1
Upgrade to mozilla-1.7.12-i486-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "mozilla-plugins", pkgver: "1.7.12", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-plugins is vulnerable in Slackware 10.1
Upgrade to mozilla-plugins-1.7.12-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "mozilla", pkgver: "1.7.12", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware 10.2
Upgrade to mozilla-1.7.12-i486-1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "mozilla-firefox", pkgver: "1.0.7", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-firefox is vulnerable in Slackware 10.2
Upgrade to mozilla-firefox-1.0.7-i686-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla", pkgver: "1.7.12", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware -current
Upgrade to mozilla-1.7.12-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla-firefox", pkgver: "1.0.7", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-firefox is vulnerable in Slackware -current
Upgrade to mozilla-firefox-1.0.7-i686-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
