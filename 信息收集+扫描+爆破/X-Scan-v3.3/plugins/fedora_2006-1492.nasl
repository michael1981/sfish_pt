
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-1492
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24080);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2006-1492: yelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-1492 (yelp)");
 script_set_attribute(attribute: "description", value: "Yelp is the Gnome 2 help/documentation browser. It is designed
to help you browse all the documentation on your system in
one central tool.

Update Information:

Mozilla Firefox is an open source Web browser.

Several flaws were found in the way Firefox processes
certain malformed JavaScript code. A malicious web page
could cause the execution of JavaScript code in such a way
that could cause Firefox to crash or execute arbitrary code
as the user running Firefox. (CVE-2006-6498, CVE-2006-6501,
CVE-2006-6502, CVE-2006-6503, CVE-2006-6504)

Several flaws were found in the way Firefox renders web
pages. A malicious web page could cause the browser to crash
or possibly execute arbitrary code as the user running
Firefox. (CVE-2006-6497)

Users of Firefox are advised to upgrade to these erratum
packages, which contain Firefox version 1.5.0.9 that
corrects these issues.


");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-6497", "CVE-2006-6501", "CVE-2006-6504");
script_summary(english: "Check for the version of the yelp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"yelp-2.16.0-11.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
