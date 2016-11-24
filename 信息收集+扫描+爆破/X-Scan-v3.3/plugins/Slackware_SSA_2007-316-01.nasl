# This script was automatically generated from the SSA-2007-316-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28149);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2007-316-01 security update');
script_set_attribute(attribute:'description', value: '
New xpdf packages are available for Slackware 9.1, 10.0, 10.1, 10.2, 11.0,
12.0, and -current.  New poppler packages are available for Slackware 12.0
and -current.  New koffice packages are available for Slackware 11.0, 12.0,
and -current.  New kdegraphics packages are available for Slackware 10.2,
11.0, 12.0, and -current.

These updated packages address similar bugs which could be used to crash
applications linked with poppler or that use code from xpdf through the
use of a malformed PDF document.  It is possible that a maliciously
crafted document could cause code to be executed in the context of the
user running the application processing the PDF.

These advisories and CVE entries cover the bugs:
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3387
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4352
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5392
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5393
  http://www.kde.org/info/security/advisory-20071107-1.txt


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2007-316-01");
script_summary("SSA-2007-316-01 xpdf/poppler/koffice/kdegraphics ");
script_name(english: "SSA-2007-316-01 xpdf/poppler/koffice/kdegraphics ");
script_cve_id("CVE-2007-3387","CVE-2007-4352","CVE-2007-5392","CVE-2007-5393");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.1", pkgname: "xpdf", pkgver: "3.02pl2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xpdf is vulnerable in Slackware 9.1
Upgrade to xpdf-3.02pl2-i486-1_slack9.1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "xpdf", pkgver: "3.02pl2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xpdf is vulnerable in Slackware 10.0
Upgrade to xpdf-3.02pl2-i486-1_slack10.0 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "xpdf", pkgver: "3.02pl2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xpdf is vulnerable in Slackware 10.1
Upgrade to xpdf-3.02pl2-i486-1_slack10.1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "kdegraphics", pkgver: "3.4.2", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kdegraphics is vulnerable in Slackware 10.2
Upgrade to kdegraphics-3.4.2-i486-3_slack10.2 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "xpdf", pkgver: "3.02pl2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xpdf is vulnerable in Slackware 10.2
Upgrade to xpdf-3.02pl2-i486-1_slack10.2 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "kdegraphics", pkgver: "3.5.4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kdegraphics is vulnerable in Slackware 11.0
Upgrade to kdegraphics-3.5.4-i486-2_slack11.0 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "koffice", pkgver: "1.5.2", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package koffice is vulnerable in Slackware 11.0
Upgrade to koffice-1.5.2-i486-5_slack11.0 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "xpdf", pkgver: "3.02pl2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xpdf is vulnerable in Slackware 11.0
Upgrade to xpdf-3.02pl2-i486-1_slack11.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "kdegraphics", pkgver: "3.5.7", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kdegraphics is vulnerable in Slackware 12.0
Upgrade to kdegraphics-3.5.7-i486-2_slack12.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "poppler", pkgver: "0.6.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package poppler is vulnerable in Slackware 12.0
Upgrade to poppler-0.6.2-i486-1_slack12.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "koffice", pkgver: "1.6.3", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package koffice is vulnerable in Slackware 12.0
Upgrade to koffice-1.6.3-i486-2_slack12.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "xpdf", pkgver: "3.02pl2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xpdf is vulnerable in Slackware 12.0
Upgrade to xpdf-3.02pl2-i486-1_slack12.0 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kdegraphics", pkgver: "3.5.8", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package kdegraphics is vulnerable in Slackware -current
Upgrade to kdegraphics-3.5.8-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "koffice", pkgver: "1.6.3", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package koffice is vulnerable in Slackware -current
Upgrade to koffice-1.6.3-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "poppler", pkgver: "0.6.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package poppler is vulnerable in Slackware -current
Upgrade to poppler-0.6.2-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "xpdf", pkgver: "3.02pl2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xpdf is vulnerable in Slackware -current
Upgrade to xpdf-3.02pl2-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
