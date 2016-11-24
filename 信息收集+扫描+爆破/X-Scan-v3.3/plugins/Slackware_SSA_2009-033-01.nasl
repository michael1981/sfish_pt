# This script was automatically generated from the SSA-2009-033-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(35577);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2009-033-01 security update');
script_set_attribute(attribute:'description', value: '
New xdg-utils packages are available for Slackware 12.2 and -current to
fix security issues.  Applications that use /etc/mailcap could be tricked
into running an arbitrary script through xdg-open, and a separate flaw in
xdg-open could allow the execution of arbitrary commands embedded in untrusted
input provided to xdg-open.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0068
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0386


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2009-033-01");
script_summary("SSA-2009-033-01 xdg-utils ");
script_name(english: "SSA-2009-033-01 xdg-utils ");
script_cve_id("CVE-2008-0386","CVE-2009-0068");
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "12.2", pkgname: "xdg-utils", pkgver: "1.0.2", pkgnum:  "3", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xdg-utils is vulnerable in Slackware 12.2
Upgrade to xdg-utils-1.0.2-noarch-3_slack12.2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "xdg-utils", pkgver: "1.0.2", pkgnum:  "3", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package xdg-utils is vulnerable in Slackware -current
Upgrade to xdg-utils-1.0.2-noarch-3 or newer.
');
}

if (w) { security_warning(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
