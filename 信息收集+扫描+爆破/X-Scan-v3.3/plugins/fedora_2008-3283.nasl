
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-3283
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32044);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-3283: Miro");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-3283 (Miro)");
 script_set_attribute(attribute: "description", value: "Miro is a free application that turns your computer into an
internet TV video player. This release is still a beta version, which means
that there are some bugs, but we're moving quickly to fix them and will be
releasing bug fixes on a regular basis.

-
Update Information:

Mozilla Firefox is an open source Web browser.    A flaw was found in the
processing of malformed JavaScript content. A web page containing such maliciou
s
content could cause Firefox to crash or, potentially, execute arbitrary code as
the user running Firefox. (CVE-2008-1380)    All Firefox users should upgrade t
o
these updated packages, which contain backported patches that correct these
issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-1380");
script_summary(english: "Check for the version of the Miro package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"Miro-1.2-2.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
