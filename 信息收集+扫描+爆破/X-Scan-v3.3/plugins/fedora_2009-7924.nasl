
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-7924
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40424);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-7924: pdfedit");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-7924 (pdfedit)");
 script_set_attribute(attribute: "description", value: "Free pdf editing using PdfEdit. Complete editing of pdf documents is made
possible with PDFedit. You can change either raw pdf objects (for advanced
users) or use predefined gui functions. Functions can be easily added as
everything is based on a script.

-
Update Information:

Update to new upstream version 0.4.3 fixing multiple issues:    * xpdf code bas
e
updated to 3.02pl3 patch which fixes    several serious remote vulnerabilities

Update information :

* French translation update (bug 275)  * Fix for [33853] Secunia advisory
backported from poppler  * Flattener class implemented (bt#289)  * Bugs 248,
256, 285, ...
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the pdfedit package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"pdfedit-0.4.3-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
