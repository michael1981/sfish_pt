
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-642
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25747);
 script_version ("$Revision: 1.5 $");
script_name(english: "Fedora 6 2007-642: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-642 (firefox)");
 script_set_attribute(attribute: "description", value: "Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

Update Information:

Mozilla Firefox is an open-source web browser, designed for
standards compliance, performance and portability.

Several flaws were found in the way Firefox processed
certain malformed JavaScript code. A web page containing
malicious JavaScript code could cause Firefox to crash or
potentially execute arbitrary code as the user running
Firefox. (CVE-2007-3734, CVE-2007-3735)

Several flaws were found in the way Firefox handles certain
JavaScript code. A web page containing malicious JavaScript
code could inject arbitrary content into other web pages.
(CVE-2007-3736, CVE-2007-3089)

A flaw was found in the way Firefox cached web pages on the
local disk. A malicious web page may be able to inject
arbitrary HTML into a browsing session if the user reloads a
targeted site. (CVE-2007-3656)

A flaw was found in the way Firefox processes certain web
content. A web page containing malicious content could
execute arbitrary commands as the user running Firefox.
(CVE-2007-3737, CVE-2007-3738)

Users of Firefox are advised to upgrade to these erratum
packages, which contain backported patches that correct
these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3735", "CVE-2007-3738");
script_summary(english: "Check for the version of the firefox package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"firefox-1.5.0.12-4.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
