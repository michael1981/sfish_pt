# This script was automatically generated from the SSA-2008-217-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(33824);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2008 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the SSA-2008-217-01 security update." );
 script_set_attribute(attribute:"description", value:
"New python packages are available for Slackware 10.1, 10.2, 11.0, 12.0,
12.1, and -current to fix security issues.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1679
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1721
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2315
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2316
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3142
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3144" );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_end_attributes();


script_xref(name: "SSA", value: "2008-217-01");
script_summary("SSA-2008-217-01 python ");
name["english"] = "SSA-2008-217-01 python ";
script_name(english:name["english"]);
script_cve_id("CVE-2008-1679","CVE-2008-1721","CVE-2008-2315","CVE-2008-2316","CVE-2008-3142","CVE-2008-3144");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "10.1", pkgname: "python", pkgver: "2.4.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware 10.1
Upgrade to python-2.4.5-i486-1_slack10.1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "python-demo", pkgver: "2.4.5", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-demo is vulnerable in Slackware 10.1
Upgrade to python-demo-2.4.5-noarch-1_slack10.1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "python-tools", pkgver: "2.4.5", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-tools is vulnerable in Slackware 10.1
Upgrade to python-tools-2.4.5-noarch-1_slack10.1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "python", pkgver: "2.4.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware 10.2
Upgrade to python-2.4.5-i486-1_slack10.2 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "python-demo", pkgver: "2.4.5", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-demo is vulnerable in Slackware 10.2
Upgrade to python-demo-2.4.5-noarch-1_slack10.2 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "python-tools", pkgver: "2.4.5", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-tools is vulnerable in Slackware 10.2
Upgrade to python-tools-2.4.5-noarch-1_slack10.2 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "python", pkgver: "2.4.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware 11.0
Upgrade to python-2.4.5-i486-1_slack11.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "python", pkgver: "2.5.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware 12.0
Upgrade to python-2.5.2-i486-1_slack12.0 or newer.
');
}
if (slackware_check(osver: "12.1", pkgname: "python", pkgver: "2.5.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware 12.1
Upgrade to python-2.5.2-i486-2_slack12.1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "python", pkgver: "2.5.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware -current
Upgrade to python-2.5.2-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, extra: desc); }
