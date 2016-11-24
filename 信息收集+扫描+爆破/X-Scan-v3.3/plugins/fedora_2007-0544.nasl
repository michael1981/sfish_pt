
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-0544
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27670);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-0544: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-0544 (thunderbird)");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

-
Update Information:

This update fixes two security issues found in the 2.0.0.0 version of Thunderbi
rd.

Details at:
[8]http://www.mozilla.org/security/announce/2007/mfsa2007-12.html
[9]http://www.mozilla.org/security/announce/2007/mfsa2007-15.html

Users of Thunderbird are recommended to update to this erratum package which fi
xes those issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868");
script_summary(english: "Check for the version of the thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"thunderbird-2.0.0.4-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
