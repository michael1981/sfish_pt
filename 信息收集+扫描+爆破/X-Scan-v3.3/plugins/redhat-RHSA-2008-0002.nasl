
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29875);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0002: tog");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0002");
 script_set_attribute(attribute: "description", value: '
  Updated tog-pegasus packages that fix a security issue are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The tog-pegasus packages provide OpenPegasus Web-Based Enterprise
  Management (WBEM) services. WBEM is a platform and resource independent
  DMTF standard that defines a common information model, and communication
  protocol for monitoring and controlling resources.

  During a security audit, a stack buffer overflow flaw was found in the PAM
  authentication code in the OpenPegasus CIM management server. An
  unauthenticated remote user could trigger this flaw and potentially execute
  arbitrary code with root privileges. (CVE-2008-0003)

  Note that the tog-pegasus packages are not installed by default on Red Hat
  Enterprise Linux. The Red Hat Security Response Team believes that it would
  be hard to remotely exploit this issue to execute arbitrary code, due to
  the default SELinux targeted policy on Red Hat Enterprise Linux 4 and 5,
  and the SELinux memory protection tests enabled by default on Red Hat
  Enterprise Linux 5.

  Users of tog-pegasus should upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing the
  updated packages the tog-pegasus service should be restarted.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0002.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0003");
script_summary(english: "Check for the version of the tog packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tog-pegasus-2.6.1-2.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tog-pegasus-devel-2.6.1-2.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tog-pegasus-2.5.1-5.el4_6.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tog-pegasus-devel-2.5.1-5.el4_6.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tog-pegasus-test-2.5.1-5.el4_6.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tog-pegasus-2.5.1-2.el4_5.1", release:'RHEL4.5.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tog-pegasus-devel-2.5.1-2.el4_5.1", release:'RHEL4.5.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tog-pegasus-test-2.5.1-2.el4_5.1", release:'RHEL4.5.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
