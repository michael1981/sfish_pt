# This script was automatically generated from the SSA-2007-066-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(24788);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2007 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the SSA-2007-066-02 security update." );
 script_set_attribute(attribute:"description", value:
"New x11 packages are available for Slackware 10.2 and 11.0.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6101
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6102
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6103" );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_end_attributes();


script_xref(name: "SSA", value: "2007-066-02");
script_summary("SSA-2007-066-02 x11 ");
name["english"] = "SSA-2007-066-02 x11 ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-6101","CVE-2006-6102","CVE-2006-6103");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "10.2", pkgname: "x11", pkgver: "6.8.2", pkgnum:  "8", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11 is vulnerable in Slackware 10.2
Upgrade to x11-6.8.2-i486-8_slack10.2 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "x11", pkgver: "6.9.0", pkgnum:  "12", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11 is vulnerable in Slackware 11.0
Upgrade to x11-6.9.0-i486-12_slack11.0 or newer.
');
}

if (w) { security_hole(port: 0, extra: desc); }
