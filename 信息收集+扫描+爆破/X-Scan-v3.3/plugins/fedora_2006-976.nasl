
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-976
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24180);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-976: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-976 (firefox)");
 script_set_attribute(attribute: "description", value: "Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

Update Information:

Mozilla Firefox is an open source Web browser.

Two flaws were found in the way Firefox processed certain
regular expressions. A malicious web page could crash the
browser or possibly execute arbitrary code as the user
running Firefox. (CVE-2006-4565, CVE-2006-4566)

A number of flaws were found in Firefox. A malicious web
page could crash the browser or possibly execute arbitrary
code as the user running Firefox. (CVE-2006-4571)

A flaw was found in the handling of JavaScript timed events.
A malicious web page could crash the browser or possibly
execute arbitrary code as the user running Firefox.
(CVE-2006-4253)

A flaw was found in the Firefox auto-update verification
system. An attacker who has the ability to spoof a victim's
DNS could get Firefox to download and install malicious
code. In order to exploit this issue an attacker would also
need to get a victim to previously accept an unverifiable
certificate. (CVE-2006-4567)

Firefox did not properly prevent a frame in one domain from
injecting content into a sub-frame that belongs to another
domain, which facilitates website spoofing and other attacks
(CVE-2006-4568)

Firefox did not load manually opened, blocked popups in the
right domain context, which could lead to cross-site
scripting attacks. In order to exploit this issue an
attacker would need to find a site which would frame their
malicious page and convince the user to manually open a
blocked popup. (CVE-2006-4569)

Users of Firefox are advised to upgrade to this update,
which contains Firefox version 1.5.0.7 that corrects these
issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-4253", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4568", "CVE-2006-4569", "CVE-2006-4571");
script_summary(english: "Check for the version of the firefox package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"firefox-1.5.0.7-1.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
