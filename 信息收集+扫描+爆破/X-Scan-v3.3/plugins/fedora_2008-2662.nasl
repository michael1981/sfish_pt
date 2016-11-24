
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2662
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31689);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 7 2008-2662: kazehakase");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2662 (kazehakase)");
 script_set_attribute(attribute: "description", value: "Kazehakase is a Web browser which aims to provide
a user interface that is truly user-friendly & fully customizable.

This package uses Gecko for HTML rendering engine.
If you want to use WebKit for HTML rendering engine, install
'kazehakase-webkit' rpm instead.

-
Update Information:

Mozilla Firefox is an open source Web browser.    Several flaws were found in
the processing of some malformed web content. A web page containing such
malicious content could cause Firefox to crash or, potentially, execute
arbitrary code as the user running Firefox. (CVE-2008-1233, CVE-2008-1235,
CVE-2008-1236, CVE-2008-1237)    Several flaws were found in the display of
malformed web content. A web page containing specially-crafted content could,
potentially, trick a Firefox user into surrendering sensitive information.
(CVE-2008-1234, CVE-2008-1238, CVE-2008-1241)    All Firefox users should
upgrade to these updated packages, which correct these issues, and are rebuilt
against the update Firefox packages.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1241");
script_summary(english: "Check for the version of the kazehakase package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kazehakase-0.5.3-5.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
