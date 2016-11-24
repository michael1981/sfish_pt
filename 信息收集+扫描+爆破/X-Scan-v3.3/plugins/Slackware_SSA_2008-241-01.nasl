# This script was automatically generated from the SSA-2008-241-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(34061);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the SSA-2008-241-01 security update." );
 script_set_attribute(attribute:"description", value:
"New Amarok packages are available for Slackware 11.0, 12.0, 12.1, and -current
to fix security issues.  In addition, new supporting libgpod packages are
available for Slackware 11.0 and 12.0, since a newer version of libgpod than
shipped with these releases is required to run Amarok version 1.4.10.

The Magnatune music library plugin made insecure use of the /tmp directory,
allowing malicious local users to overwrite files owned by the user running
Amarok through symlink attacks.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3699" );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
script_end_attributes();


script_xref(name: "SSA", value: "2008-241-01");
script_summary(english:"SSA-2008-241-01 amarok ");
name["english"] = "SSA-2008-241-01 amarok ";
script_name(english:name["english"]);
script_cve_id("CVE-2008-3699");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "11.0", pkgname: "amarok", pkgver: "1.4.10", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package amarok is vulnerable in Slackware 11.0
Upgrade to amarok-1.4.10-i486-1_slack11.0 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "libgpod", pkgver: "0.6.0", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package libgpod is vulnerable in Slackware 11.0
Upgrade to libgpod-0.6.0-i486-1_slack11.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "amarok", pkgver: "1.4.10", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package amarok is vulnerable in Slackware 12.0
Upgrade to amarok-1.4.10-i486-1_slack12.0 or newer.
');
}
if (slackware_check(osver: "12.0", pkgname: "libgpod", pkgver: "0.6.0", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package libgpod is vulnerable in Slackware 12.0
Upgrade to libgpod-0.6.0-i486-1_slack12.0 or newer.
');
}
if (slackware_check(osver: "12.1", pkgname: "amarok", pkgver: "1.4.10", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package amarok is vulnerable in Slackware 12.1
Upgrade to amarok-1.4.10-i486-1_slack12.1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "amarok", pkgver: "1.4.10", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package amarok is vulnerable in Slackware -current
Upgrade to amarok-1.4.10-i486-1 or newer.
');
}

if (w) { security_note(port: 0, extra: desc); }
