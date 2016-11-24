
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8429
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34309);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-8429: seamonkey");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8429 (seamonkey)");
 script_set_attribute(attribute: "description", value: "SeaMonkey is an all-in-one Internet application suite. It includes
a browser, mail/news client, IRC client, JavaScript debugger, and
a tool to inspect the DOM for web pages. It is derived from the
application formerly known as Mozilla Application Suite.

-
Update Information:

Updated seamonkey packages that fix several security issues are now available
for Fedora 8 and Fedora 9.    This update has been rated as having critical
security impact by the Red Hat Security Response Team.    SeaMonkey is an open
source Web browser, advanced email and newsgroup client, IRC chat client, and
HTML editor.    Several flaws were found in the processing of malformed web
content. A web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code as the user running SeaMonkey.
(CVE-2008-0016, CVE-2008-4058, CVE-2008-4059, CVE-2008-4060, CVE-2008-4061,
CVE-2008-4062)    Several flaws were found in the way malformed web content was
displayed. A web page containing specially crafted content could potentially
trick a SeaMonkey user into surrendering sensitive information. (CVE-2008-3835,
CVE-2008-4067, CVE-2008-4068, CVE-2008-4069)    A flaw was found in the way
SeaMonkey handles mouse click events. A web page containing specially crafted
JavaScript code could move the content window while a mouse-button was pressed,
causing any item under the pointer to be dragged. This could, potentially, caus
e
the user to perform an unsafe drag-and-drop action. (CVE-2008-3837)    A flaw
was found in SeaMonkey that caused certain characters to be stripped from
JavaScript code. This flaw could allow malicious JavaScript to bypass or evade
script filters. (CVE-2008-4065, CVE-2008-4066)    All SeaMonkey users should
upgrade to these updated packages, which contain patches to resolve these
issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3835", "CVE-2008-3837", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4066", "CVE-2008-4069");
script_summary(english: "Check for the version of the seamonkey package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"seamonkey-1.1.12-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
