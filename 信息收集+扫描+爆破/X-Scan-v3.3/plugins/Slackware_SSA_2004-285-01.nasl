# This script was automatically generated from the SSA-2004-285-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(18780);
script_version("$Revision: 1.8 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the SSA-2004-285-01 security update." );
 script_set_attribute(attribute:"description", value:
"New rsync 2.6.3 packages are available for Slackware 8.1, 9.0, 9.1,
10.0, and -current to a fix security issue when rsync is run as
a non-chrooted server.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-792" );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_end_attributes();


script_xref(name: "SSA", value: "2004-285-01");
script_summary("SSA-2004-285-01 rsync ");
name["english"] = "SSA-2004-285-01 rsync ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0792");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "8.1", pkgname: "rsync", pkgver: "2.6.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package rsync is vulnerable in Slackware 8.1
Upgrade to rsync-2.6.3-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "rsync", pkgver: "2.6.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package rsync is vulnerable in Slackware 9.0
Upgrade to rsync-2.6.3-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "rsync", pkgver: "2.6.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package rsync is vulnerable in Slackware 9.1
Upgrade to rsync-2.6.3-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "rsync", pkgver: "2.6.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package rsync is vulnerable in Slackware 10.0
Upgrade to rsync-2.6.3-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "rsync", pkgver: "2.6.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package rsync is vulnerable in Slackware -current
Upgrade to rsync-2.6.3-i486-1 or newer.
');
}

if (w) { security_warning(port: 0, extra: desc); }
