# This script was automatically generated from the SSA-2006-114-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21272);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2006-114-01 security update');
script_set_attribute(attribute:'description', value: '
New Mozilla packages are available for Slackware 10.0, 10.1,
10.2 and -current to fix multiple security issues.

More details about the issues may be found here:

  http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla

Also note that this release marks the EOL (End Of Life) for the Mozilla
Suite series.  It\'s been a great run, so thanks to everyone who put in
so much effort to make Mozilla a great browser suite.  In the next
Slackware release fans of the Mozilla Suite will be able to look
forward to browsing with SeaMonkey, the Suite\'s successor.  Anyone
using an older version of Slackware may want to start thinking about
migrating to another browser -- if not now, when the next problems
with Mozilla are found.

Although the "sunset announcement" states that mozilla-1.7.13 is the
final mozilla release, I wouldn\'t be too surprised to see just one
more since there\'s a Makefile.in bug that needed to be patched here
before Mozilla 1.7.13 would build.  If a new release comes out and
fixes only that issue, don\'t look for a package release on that as
it\'s already fixed in these packages.  If additional issues are
fixed, then there will be new packages.  Basically, if upstream
un-EOLs this for a good reason, so will we.


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2006-114-01");
script_summary("SSA-2006-114-01 mozilla security/EOL ");
script_name(english: "SSA-2006-114-01 mozilla security/EOL ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "10.0", pkgname: "mozilla", pkgver: "1.7.13", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware 10.0
Upgrade to mozilla-1.7.13-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "mozilla-plugins", pkgver: "1.7.13", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-plugins is vulnerable in Slackware 10.0
Upgrade to mozilla-plugins-1.7.13-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "mozilla", pkgver: "1.7.13", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware 10.1
Upgrade to mozilla-1.7.13-i486-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "mozilla-plugins", pkgver: "1.7.13", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla-plugins is vulnerable in Slackware 10.1
Upgrade to mozilla-plugins-1.7.13-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "mozilla", pkgver: "1.7.13", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware 10.2
Upgrade to mozilla-1.7.13-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla", pkgver: "1.7.13", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package mozilla is vulnerable in Slackware -current
Upgrade to mozilla-1.7.13-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
