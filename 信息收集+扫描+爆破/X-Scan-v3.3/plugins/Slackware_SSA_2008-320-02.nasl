# This script was automatically generated from the SSA-2008-320-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2008 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2008 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(34783);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2008 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the SSA-2008-320-02 security update." );
 script_set_attribute(attribute:"description", value:
"New net-snmp packages are available for Slackware 12.0, 12.1, and -current to
fix a denial of service issue.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4309" );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_end_attributes();


script_xref(name: "SSA", value: "2008-320-02");
script_summary("SSA-2008-320-02 net-snmp ");
name["english"] = "SSA-2008-320-02 net-snmp ";
script_name(english:name["english"]);
script_cve_id("CVE-2008-4309");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "12.0", pkgname: "net-snmp", pkgver: "5.4.2.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package net-snmp is vulnerable in Slackware 12.0
Upgrade to net-snmp-5.4.2.1-i486-1_slack12.0 or newer.
');
}
if (slackware_check(osver: "12.1", pkgname: "net-snmp", pkgver: "5.4.2.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package net-snmp is vulnerable in Slackware 12.1
Upgrade to net-snmp-5.4.2.1-i486-1_slack12.1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "net-snmp", pkgver: "5.4.2.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package net-snmp is vulnerable in Slackware -current
Upgrade to net-snmp-5.4.2.1-i486-1 or newer.
');
}

if (w) { security_warning(port: 0, extra: desc); }
