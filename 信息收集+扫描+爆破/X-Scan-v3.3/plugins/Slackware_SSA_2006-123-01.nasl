# This script was automatically generated from the SSA-2006-123-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21342);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2006-123-01 security update');
script_set_attribute(attribute:'description', value: '
New xorg and xorg-devel packages are available for Slackware 10.1, 10.2,
and -current to fix a security issue.  A typo in the X render extension
in X.Org 6.8.0 or later allows an X client to crash the server and
possibly to execute arbitrary code as the X server user (typically this
is "root".)

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1526

The advisory from X.Org may be found here:

  http://lists.freedesktop.org/archives/xorg/2006-May/015136.html


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2006-123-01");
script_summary("SSA-2006-123-01 xorg server overflow ");
script_name(english: "SSA-2006-123-01 xorg server overflow ");
script_cve_id("CVE-2006-1526");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "10.1", pkgname: "x11", pkgver: "6.8.1", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package x11 is vulnerable in Slackware 10.1
Upgrade to x11-6.8.1-i486-5 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "x11-devel", pkgver: "6.8.1", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package x11-devel is vulnerable in Slackware 10.1
Upgrade to x11-devel-6.8.1-i486-5 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "x11", pkgver: "6.8.2", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package x11 is vulnerable in Slackware 10.2
Upgrade to x11-6.8.2-i486-5 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "x11-devel", pkgver: "6.8.2", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package x11-devel is vulnerable in Slackware 10.2
Upgrade to x11-devel-6.8.2-i486-5 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11", pkgver: "6.9.0", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package x11 is vulnerable in Slackware -current
Upgrade to x11-6.9.0-i486-4 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11-devel", pkgver: "6.9.0", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package x11-devel is vulnerable in Slackware -current
Upgrade to x11-devel-6.9.0-i486-4 or newer.
');
}

if (w) { security_note(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
