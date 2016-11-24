
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8432
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40534);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 10 2009-8432: subversion");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8432 (subversion)");
 script_set_attribute(attribute: "description", value: "Subversion is a concurrent version control system which enables one
or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes.  Subversion only stores the differences between versions,
instead of every complete file.  Subversion is intended to be a
compelling replacement for CVS.

-
Update Information:

This update includes the latest stable release of Subversion, including several
enhancements, many bug fixes, and a fix for a security issue:    Matt Lewis
reported multiple heap overflow flaws in Subversion (servers and clients) when
parsing binary deltas. Malicious users with commit access to a vulnerable serve
r
could uses these flaws to cause a heap overflow on the server running
Subversion. A malicious Subversion server could use these flaws to cause a heap
overflow on vulnerable clients when they attempt to checkout or update,
resulting in a crash or, possibly, arbitrary code execution on the vulnerable
client. (CVE-2009-2411)    Version 1.6 offers many bug fixes and enhancements
over 1.5, with the notable major features:    - identical files share storage
space in repository  - file-externals support for intra-repository files  -
'tree' conflicts now handled more gracefully  - repository root relative URL
support on most commands    For more information on changes in 1.6, see the
release notes:    [9]http://subversion.tigris.org/svn_1.6_releasenotes.html
This
update includes the latest release of Subversion, version 1.6.2.    Version 1.6
offers many bug fixes and enhancements over 1.5, with the notable major
features:     * identical files share storage space in repository   * file-
externals support for intra-repository files   * 'tree' conflicts now handled
more gracefully   * repository root relative URL support on most commands
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2411");
script_summary(english: "Check for the version of the subversion package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"subversion-1.6.4-2.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
