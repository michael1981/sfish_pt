
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2884
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35984);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-2884: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2884 (thunderbird)");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

-
Update Information:

Several flaws were found in the processing of malformed HTML mail content. An
HTML mail message containing malicious content could cause Thunderbird to crash
or, potentially, execute arbitrary code as the user running Thunderbird.
(CVE-2009-0040, CVE-2009-0352, CVE-2009-0353, CVE-2009-0772, CVE-2009-0774,
CVE-2009-0775)    Several flaws were found in the way malformed content was
processed. An HTML mail message containing specially-crafted content could
potentially trick a Thunderbird user into surrendering sensitive information.
(CVE-2009-0355, CVE-2009-0776)    Note: JavaScript support is disabled by
default in Thunderbird. None of the above issues are exploitable unless
JavaScript is enabled.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0355", "CVE-2009-0772", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776");
script_summary(english: "Check for the version of the thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"thunderbird-2.0.0.21-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
