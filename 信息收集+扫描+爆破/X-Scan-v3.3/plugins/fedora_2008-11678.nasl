
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11678
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36570);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2008-11678: git");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11678 (git)");
 script_set_attribute(attribute: "description", value: "Git is a fast, scalable, distributed revision control system with an
unusually rich command set that provides both high-level operations
and full access to internals.

The git rpm installs the core tools with minimal dependencies.  To
install all git packages, including tools for integrating with other
SCMs, install the git-all meta-package.

-
Update Information:

This update fixes a local privilege escalation bug in gitweb.  For details:
[9]http://article.gmane.org/gmane.comp.version-control.git/103624    There are
also
a number of bugs fixed upstream.  For details, see the upstream release notes:
[10]http://www.kernel.org/pub/software/scm/git/docs/RelNotes-1.6.0.6.txt    Git
k has
been added as a requirement of git-gui (bug 476308)  Update to 1.6.0.5 to pick
up a number of smaller bugfixes from upstream
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the git package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"git-1.6.0.6-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
