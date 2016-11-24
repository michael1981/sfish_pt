# This script was automatically generated from the SSA-2007-243-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2009 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(25957);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2009 Tenable Network Security, Inc.");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");

script_set_attribute(attribute:'synopsis', value:
'The remote host is missing the SSA-2007-243-01 security update');
script_set_attribute(attribute:'description', value: '
Sun has released security advisories pertaining to both the Java
Runtime Environment and the Standard Edition Development Kit.  

One such advisory may be found here:
  http://sunsolve.sun.com/search/document.do?assetkey=1-26-102995-1

Updated versions of both the jre and jdk packages are provided
which address all known flaws in Java(TM) at this time.  There
may be more advisories on http://sunsolve.sun.com describing other
flaws that are patched with this update.  Happy hunting!

Slackware repackages Sun\'s Java(TM) binaries without changing them,
so the packages from Slackware 12.0 should work on all glibc based
Slackware versions.


');
script_set_attribute(attribute:'solution', value: 
'Update the packages that are referenced in the security advisory.');
script_xref(name: "SSA", value: "2007-243-01");
script_summary("SSA-2007-243-01 java (jre, jdk) ");
script_name(english: "SSA-2007-243-01 java (jre, jdk) ");
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if ( ! get_kb_item('Host/Slackware/packages') ) exit(1, 'Could not obtain the list of packages');

extrarep = NULL;
if (slackware_check(osver: "12.0", pkgname: "jre", pkgver: "6u2", pkgnum:  "1", pkgarch: "i586")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package jre is vulnerable in Slackware 12.0
Upgrade to jre-6u2-i586-1 or newer.
');
}
if (slackware_check(osver: "", pkgname: "jdk", pkgver: "6u2", pkgnum:  "1", pkgarch: "i586")) {
w++;
if (report_verbosity > 0) extrarep = strcat(extrarep, '
The package jdk is vulnerable in Slackware 
Upgrade to jdk-6u2-i586-1 or newer.
');
}

if (w) { security_hole(port: 0, extra: extrarep); }

else exit(0, "Host is not affected");
