
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35605);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0267: sudo");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0267");
 script_set_attribute(attribute: "description", value: '
  An updated sudo package to fix a security issue is now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The sudo (superuser do) utility allows system administrators to give
  certain users the ability to run commands as root with logging.

  A flaw was discovered in a way sudo handled group specifications in "run
  as" lists in the sudoers configuration file. If sudo configuration allowed
  a user to run commands as any user of some group and the user was also a
  member of that group, sudo incorrectly allowed them to run defined commands
  with the privileges of any system user. This gave the user unintended
  privileges. (CVE-2009-0034)

  Users of sudo should update to this updated package, which contains a
  backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0267.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0034");
script_summary(english: "Check for the version of the sudo packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sudo-1.6.9p17-3.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
