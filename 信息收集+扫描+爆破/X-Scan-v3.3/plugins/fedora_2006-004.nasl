
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-004
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24027);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-004: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-004 (thunderbird)");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

Update Information:

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the way Thunderbird processes
certain malformed JavaScript code. A malicious web page
could cause the execution of JavaScript code in such a way
that could cause Thunderbird to crash or execute arbitrary
code as the user running Thunderbird. JavaScript support is
disabled by default in Thunderbird; this issue is not
exploitable without enabling JavaScript. (CVE-2006-6498,
CVE-2006-6501, CVE-2006-6502, CVE-2006-6503, CVE-2006-6504)

Several flaws were found in the way Thunderbird renders web
pages. A malicious web page could cause the browser to crash
or possibly execute arbitrary code as the user running
Thunderbird. (CVE-2006-6497)

A heap based buffer overflow flaw was found in the way
Thunderbird parses the Content-Type mail header. A malicious
mail message could cause the Thunderbird client to crash or
possibly execute arbitrary code as the user running
Thunderbird. (CVE-2006-6505)

Users of Thunderbird are advised to apply this update, which
contains Thunderbird version 1.5.0.9 that corrects these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6504", "CVE-2006-6505");
script_summary(english: "Check for the version of the thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"thunderbird-1.5.0.9-2.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
