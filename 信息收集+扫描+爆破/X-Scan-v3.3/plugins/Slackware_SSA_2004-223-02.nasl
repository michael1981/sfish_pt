# This script was automatically generated from the SSA-2004-223-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(18749);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2004-223-02 security update');
script_set_attribute(attribute:'description', value: '
New imagemagick packages are available for Slackware 9.1, 10.0,
and -current to fix security issues with PNG images.

More details about the issues with PNG may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0597
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0598
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0599

');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2004-223-02");
script_summary("SSA-2004-223-02 imagemagick ");
script_name(english: "SSA-2004-223-02 imagemagick ");
script_cve_id("CVE-2004-0597","CVE-2004-0598","CVE-2004-0599");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "9.1", pkgname: "imagemagick", pkgver: "5.5.7_25", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package imagemagick is vulnerable in Slackware 9.1
Upgrade to imagemagick-5.5.7_25-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "imagemagick", pkgver: "6.0.4_3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package imagemagick is vulnerable in Slackware 10.0
Upgrade to imagemagick-6.0.4_3-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "imagemagick", pkgver: "6.0.4_3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package imagemagick is vulnerable in Slackware -current
Upgrade to imagemagick-6.0.4_3-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
