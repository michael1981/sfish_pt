
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8279
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40483);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-8279: gnome-web-photo");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8279 (gnome-web-photo)");
 script_set_attribute(attribute: "description", value: "gnome-web-photo contains a thumbnailer that will be used by GNOME applications,
including the file manager, to generate screenshots of web pages.

-
Update Information:

Update to new upstream Firefox version 3.5.2, fixing multiple security issues
detailed in the upstream advisories:    [9]http://www.mozilla.org/security/know
n-
vulnerabilities/firefox35.html#firefox3.5.2    Update also includes all package
s
depending on gecko-libs rebuilt against new version of Firefox / XULRunner.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the gnome-web-photo package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gnome-web-photo-0.7-5.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
