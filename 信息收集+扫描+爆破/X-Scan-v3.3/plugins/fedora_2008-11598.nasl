
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11598
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35238);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-11598: epiphany");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11598 (epiphany)");
 script_set_attribute(attribute: "description", value: "Epiphany is a simple GNOME web browser based on the Mozilla rendering
engine.

-
Update Information:

Update to the new upstream Firefox 3.0.5 / XULRunner 1.9.0.5 fixing multiple
security issues:  [9]http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.5    This update also contains new
builds of all applications depending on Gecko libraries, built against  thenew
version.    Note: after the updated packages are installed, Firefox must be
restarted for the update to take effect.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5505", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
script_summary(english: "Check for the version of the epiphany package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"epiphany-2.22.2-6.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
