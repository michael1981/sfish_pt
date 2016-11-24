
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11551
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35233);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-11551: devhelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11551 (devhelp)");
 script_set_attribute(attribute: "description", value: "An API document browser for GNOME 2.

-
Update Information:

Update to the new upstream Firefox release 2.0.0.19 fixing multiple security
issues:  [9]http://www.mozilla.org/security/known-
vulnerabilities/firefox20.html#firefox2.0.0.19    This update also contains new
builds of all applications depending on Gecko libraries, built against the new
version.    Note: after the updated packages are installed, Firefox must be
restarted for the update to take effect.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
script_summary(english: "Check for the version of the devhelp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"devhelp-0.16.1-12.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
