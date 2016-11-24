# This script was automatically generated from a
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);


include("compat.inc");

if (description) {
script_id(18708);
script_version("$Revision: 1.7 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update." );
 script_set_attribute(attribute:"description", value:
"New cvs packages are available to fix a security vulnerability." );
 script_set_attribute(attribute:"solution", value:
"Update the packages that are referenced in the security advisory." );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_end_attributes();


script_summary(english:"SSA New CVS packages available");
name["english"] = "SSA-18708 New CVS packages available";
script_name(english:name["english"]);script_cve_id("CVE-2003-0015");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

desc="";
if (slackware_check(osver: "8.1", pkgname: "cvs", pkgver: "1.11.5", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package cvs is vulnerable in Slackware 8.1
Upgrade to cvs-1.11.5-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "cvs", pkgver: "1.11.5", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package cvs is vulnerable in Slackware -current
Upgrade to cvs-1.11.5-i386-1 or newer.
');
}

if (w) { security_warning(port: 0, extra: desc); }
