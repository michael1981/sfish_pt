
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2635
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27782);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2635: subversion");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2635 (subversion)");
 script_set_attribute(attribute: "description", value: "Subversion is a concurrent version control system which enables one
or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes.  Subversion only stores the differences between versions,
instead of every complete file.  Subversion is intended to be a
compelling replacement for CVS.

-
Update Information:

This update includes the Subversion 1.4.4 release, including a number of bug fi
xes and a fix for a minor security issue.

An issue was discovered in the implementation of access control for revision pr
operties in the path-based authorization code.  In a repository using path-base
d access control, if a path was copied  from a private area to a public area, t
he revision properties of the (private) source path would become visible despit
e the access control restrictions.  (CVE-2007-2448)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-2448");
script_summary(english: "Check for the version of the subversion package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"subversion-1.4.4-1.fc7", release:"FC7") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
