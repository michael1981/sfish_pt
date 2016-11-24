
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2421
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35802);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-2421: mugshot");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2421 (mugshot)");
 script_set_attribute(attribute: "description", value: "Mugshot works with the server at mugshot.org to extend
the panel, web browser, music player and other parts of the desktop with
a 'live social experience' and interoperation with online services you and
your friends use. It's fun and easy.

-
Update Information:

Update to the new upstream Firefox 3.0.7 / XULRunner 1.9.0.7 fixing multiple
security issues:  [9]http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.7    This update also contains new
builds of all applications depending on Gecko libraries, built against the new
version.    Note: after the updated packages are installed, Firefox must be
restarted for the update to take effect.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777");
script_summary(english: "Check for the version of the mugshot package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mugshot-1.2.2-6.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
