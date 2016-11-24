
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12355);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-027: netscape");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-027");
 script_set_attribute(attribute: "description", value: '
  Updated Netscape 4.8 packages fixing various bugs and vulnerabilities are
  now available.

  Netscape is a suite of Internet utilities including a Web browser, email
  client, and Usenet news reader.

  Netscape version 4.8 contains various bugfixes and updates.

  Note that Macromedia Flash is no longer included as of this update. The
  recommended Macromedia Flash with security fixes no longer supports
  Netscape 4.x. The security issues that affected the Macromedia Flash
  player include CVE-2002-0846 and CAN-2002-1467.

  It is recommended that all Netscape Communicator and Netscape Navigator
  users upgrade to these errata packages.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-027.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0846", "CVE-2002-1467");
script_summary(english: "Check for the version of the netscape packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"netscape-common-4.8-1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netscape-communicator-4.8-1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netscape-navigator-4.8-1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
