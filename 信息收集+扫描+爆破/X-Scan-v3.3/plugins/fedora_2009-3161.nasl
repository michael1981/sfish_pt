
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3161
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37911);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-3161: seamonkey");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3161 (seamonkey)");
 script_set_attribute(attribute: "description", value: "SeaMonkey is an all-in-one Internet application suite. It includes
a browser, mail/news client, IRC client, JavaScript debugger, and
a tool to inspect the DOM for web pages. It is derived from the
application formerly known as Mozilla Application Suite.

-
Update Information:

[9]http://www.mozilla.org/security/known-vulnerabilities/seamonkey11.html
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0357", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-1044", "CVE-2009-1169");
script_summary(english: "Check for the version of the seamonkey package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"seamonkey-1.1.15-3.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
