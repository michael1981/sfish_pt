
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-3011
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28156);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 7 2007-3011: tomboy");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-3011 (tomboy)");
 script_set_attribute(attribute: "description", value: "Tomboy is a desktop note-taking application for Linux and Unix. Simple and easy
to use, but with potential to help you organize the ideas and information you
deal with every day.  The key to Tomboy's usefulness lies in the ability to
relate notes and ideas together.  Using a WikiWiki-like linking system,
organizing ideas is as simple as typing a name.  Branching an idea off is easy
as pressing the Link button. And links between your ideas won't break, even whe
n
renaming and reorganizing them.

-
Update Information:

This update resolves a low severity security issue where LD_LIBRARY_PATH could
potentially get set to the current directory if it wasn't set before Tomboy was
launched.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2005-4790");
script_summary(english: "Check for the version of the tomboy package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"tomboy-0.6.1-2.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
