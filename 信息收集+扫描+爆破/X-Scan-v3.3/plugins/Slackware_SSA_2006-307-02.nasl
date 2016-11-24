# This script was automatically generated from the SSA-2006-307-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(24658);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2007 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the SSA-2006-307-02 security update." );
 script_set_attribute(attribute:"description", value:
"New screen packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, and 11.0 to fix a security issue.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4573" );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
script_end_attributes();


script_xref(name: "SSA", value: "2006-307-02");
script_summary("SSA-2006-307-02 screen ");
name["english"] = "SSA-2006-307-02 screen ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-4573");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "8.1", pkgname: "screen", pkgver: "4.0.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package screen is vulnerable in Slackware 8.1
Upgrade to screen-4.0.3-i386-1_slack8.1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "screen", pkgver: "4.0.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package screen is vulnerable in Slackware 9.0
Upgrade to screen-4.0.3-i386-1_slack9.0 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "screen", pkgver: "4.0.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package screen is vulnerable in Slackware 9.1
Upgrade to screen-4.0.3-i486-1_slack9.1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "screen", pkgver: "4.0.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package screen is vulnerable in Slackware 10.0
Upgrade to screen-4.0.3-i486-1_slack10.0 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "screen", pkgver: "4.0.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package screen is vulnerable in Slackware 10.1
Upgrade to screen-4.0.3-i486-1_slack10.1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "screen", pkgver: "4.0.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package screen is vulnerable in Slackware 10.2
Upgrade to screen-4.0.3-i486-1_slack10.2 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "screen", pkgver: "4.0.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package screen is vulnerable in Slackware 11.0
Upgrade to screen-4.0.3-i486-1_slack11.0 or newer.
');
}

if (w) { security_note(port: 0, extra: desc); }
