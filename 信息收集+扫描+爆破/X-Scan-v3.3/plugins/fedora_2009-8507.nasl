
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8507
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40582);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-8507: viewvc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8507 (viewvc)");
 script_set_attribute(attribute: "description", value: "ViewVC is a browser interface for CVS and Subversion version control
repositories. It generates templatized HTML to present navigable directory,
revision, and change log listings. It can display specific versions of files
as well as diffs between those versions. Basically, ViewVC provides the bulk
of the report-like functionality you expect out of your version control tool,
but much more prettily than the average textual command-line program output.

-
Update Information:

CHANGES in 1.1.2:    - security fix: validate the 'view' parameter to avoid XSS
attack  - security fix: avoid printing illegal parameter names and values  - ad
d
optional support for character encoding detection (issue #400)  - fix username
case handling in svnauthz module (issue #419)  - fix cvsdbadmin/svnadmin rebuil
d
error on missing repos (issue #420)  - don't drop leading blank lines from
colorized file contents (issue #422)  - add file.ezt template logic for
optionally hiding binary file contents    Also includes:    Install and populat
e
mimetypes.conf. This should hopefully help when colouring syntax using pygments
.
Install and populate mimetypes.conf.
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

if ( rpm_check( reference:"viewvc-1.1.2-2.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
