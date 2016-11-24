# This script was automatically generated from the SSA-2007-314-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(28148);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2007 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the SSA-2007-314-02 security update." );
 script_set_attribute(attribute:"description", value:
"The security/bug fix update for Slackware 11.0 has been reissued
to fix a zero-length /usr/bin/php-cgi.  Thanks to TJ Munro for
pointing this out.

Sorry for any inconvenience." );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"risk_factor", value:"High" );
script_end_attributes();


script_xref(name: "SSA", value: "2007-314-02");
script_summary("SSA-2007-314-02 php for Slackware 11.0 reissued ");
name["english"] = "SSA-2007-314-02 php for Slackware 11.0 reissued ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "11.0", pkgname: "php", pkgver: "5.2.5", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 11.0
Upgrade to php-5.2.5-i486-2_slack11.0 or newer.
');
}

if (w) { security_hole(port: 0, extra: desc); }
