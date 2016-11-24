# This script was automatically generated from the SSA-2003-236-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(18717);
script_version("$Revision: 1.5 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the SSA-2003-236-01 security update." );
 script_set_attribute(attribute:"description", value:
"Upgraded gdm packages are available for Slackware 9.0 and -current.
These fix a security issue where a local user may use GDM to read any
file on the system." );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"risk_factor", value:"High" );
script_end_attributes();


script_xref(name: "SSA", value: "2003-236-01");
script_summary("SSA-2003-236-01 GDM security update ");
name["english"] = "SSA-2003-236-01 GDM security update ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "9.0", pkgname: "gdm", pkgver: "2.4.1.6", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gdm is vulnerable in Slackware 9.0
Upgrade to gdm-2.4.1.6-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "gdm", pkgver: "2.4.1.6", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gdm is vulnerable in Slackware -current
Upgrade to gdm-2.4.1.6-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: desc); }
