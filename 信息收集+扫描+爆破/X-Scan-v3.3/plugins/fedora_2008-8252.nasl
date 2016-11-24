
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8252
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34280);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-8252: viewvc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8252 (viewvc)");
 script_set_attribute(attribute: "description", value: "ViewVC is a browser interface for CVS and Subversion version control
repositories. It generates templatized HTML to present navigable directory,
revision, and change log listings. It can display specific versions of files
as well as diffs between those versions. Basically, ViewVC provides the bulk
of the report-like functionality you expect out of your version control tool,
but much more prettily than the average textual command-line program output.

-
Update Information:

Security fix: ignore arbitrary user-provided MIME types (ViewVC issue #354):
[9]http://viewvc.tigris.org/issues/show_bug.cgi?id=354
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the viewvc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"viewvc-1.0.6-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
