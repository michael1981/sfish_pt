# This script was automatically generated from the SSA-2007-152-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(25373);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2007 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the SSA-2007-152-01 security update." );
 script_set_attribute(attribute:"description", value:
"New php5 packages are available for Slackware 10.2, 11.0, and -current to
fix security issues.  PHP5 was considered a test package in Slackware 10.2,
and an 'extra' package in Slackware 11.0.  If you are currently running
PHP4 you may wish to stick with that, as upgrading to PHP5 will probably
require changes to your system's configuration and/or web code.

More details about the issues affecting Slackware's PHP5 may be found in
the Common Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1900
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2756
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2872

One CVE-issued vulnerability (CVE-2007-1887) does not affect Slackware as
we do not ship an unbundled sqlite2 library.");
 script_set_attribute(attribute:"solution", value:"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_end_attributes();


script_xref(name: "SSA", value: "2007-152-01");
script_summary("SSA-2007-152-01 php5 ");
name["english"] = "SSA-2007-152-01 php5 ";
script_name(english:name["english"]);
script_cve_id("CVE-2007-1900","CVE-2007-2756","CVE-2007-2872");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "10.2", pkgname: "php", pkgver: "5.2.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 10.2
Upgrade to php-5.2.3-i486-1_slack10.2 or newer.
');
}
if (slackware_check(osver: "11.0", pkgname: "php", pkgver: "5.2.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 11.0
Upgrade to php-5.2.3-i486-1_slack11.0 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "php", pkgver: "5.2.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware -current
Upgrade to php-5.2.3-i486-1 or newer.
');
}

if (w) { security_warning(port: 0, extra: desc); }
