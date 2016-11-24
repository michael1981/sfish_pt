
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1399
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35604);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-1399: galeon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1399 (galeon)");
 script_set_attribute(attribute: "description", value: "Galeon is a web browser built around Gecko (Mozilla's rendering
engine) and Necko (Mozilla's networking engine). It's a GNOME web
browser, designed to take advantage of as many GNOME technologies as
makes sense. Galeon was written to do just one thing - browse the web.

-
Update Information:

Update to the new upstream Firefox 3.0.6 / XULRunner 1.9.0.6 fixing multiple
security issues:  [9]http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.6    This update also contains new
builds of all applications depending on Gecko libraries, built against the new
version.    Note: after the updated packages are installed, Firefox must be
restarted for the update to take effect.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");
script_summary(english: "Check for the version of the galeon package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"galeon-2.0.7-5.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
