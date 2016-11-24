
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6518
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33542);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-6518: devhelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6518 (devhelp)");
 script_set_attribute(attribute: "description", value: "An API document browser for GNOME 2.

-
Update Information:

Updated firefox packages that fix several security issues are now available for
Fedora 9.    An integer overflow flaw was found in the way Firefox displayed
certain web content. A malicious web site could cause Firefox to crash, or
execute arbitrary code with the permissions of the user running Firefox.
(CVE-2008-2785)    A flaw was found in the way Firefox handled certain command
line URLs. If another application passed Firefox a malformed URL, it could
result in Firefox executing local malicious content with chrome privileges.
(CVE-2008-2933)    Updated packages update Mozilla Firefox to upstream version
3.0.1 to address these flaws:    [9]http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.1    This update also contains
devhelp, epiphany, epiphany-extensions, and yelp packages rebuilt against new
Firefox / Gecko libraries.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2785", "CVE-2008-2933");
script_summary(english: "Check for the version of the devhelp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"devhelp-0.19.1-3.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
