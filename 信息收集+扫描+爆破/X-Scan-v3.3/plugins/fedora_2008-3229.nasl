
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3229
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32038);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-3229: kazehakase");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3229 (kazehakase)");
 script_set_attribute(attribute: "description", value: "Kazehakase is a Web browser which aims to provide
a user interface that is truly user-friendly & fully customizable.

This package uses Gecko for HTML rendering engine.
If you want to use WebKit for HTML rendering engine, install
'kazehakase-webkit' rpm instead.

-
Update Information:

Updated WebKit packages are available which fix two security  vulnerabilities:
CVE-2008-1010 (Arbitrary code execution)  and CVE-2008-1011 (Cross-Site
Scripting).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1010", "CVE-2008-1011");
script_summary(english: "Check for the version of the kazehakase package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kazehakase-0.5.4-2.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
