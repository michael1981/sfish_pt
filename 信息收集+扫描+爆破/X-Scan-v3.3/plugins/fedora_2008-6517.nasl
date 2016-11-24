
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6517
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33541);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-6517: seamonkey");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6517 (seamonkey)");
 script_set_attribute(attribute: "description", value: "SeaMonkey is an all-in-one Internet application suite. It includes
a browser, mail/news client, IRC client, JavaScript debugger, and
a tool to inspect the DOM for web pages. It is derived from the
application formerly known as Mozilla Application Suite.

-
Update Information:

Updated seamonkey packages that fix several security issues are now available
for Fedora 8.    An integer overflow flaw was found in the way Seamonkey
displayed certain web content. A malicious web site could cause Seamonkey to
crash, or execute arbitrary code with the permissions of the user running
Seamonkey. (CVE-2008-2785)    Updated packages update Seamonkey to upstream
version 1.1.11 to address this flaw:  [9]http://www.mozilla.org/security/known-
vulnerabilities/seamonkey11.html#seamonkey1.1.11
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2785");
script_summary(english: "Check for the version of the seamonkey package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"seamonkey-1.1.11-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
