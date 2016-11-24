
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21034);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0204: mailman");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0204");
 script_set_attribute(attribute: "description", value: '
  An updated mailman package that fixes two security issues is now available
  for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mailman is software to help manage email discussion lists.

  A flaw in handling of UTF8 character encodings was found in Mailman. An
  attacker could send a carefully crafted email message to a mailing list run
  by Mailman which would cause that particular mailing list to stop working.
  The Common Vulnerabilities and Exposures project assigned the name
  CVE-2005-3573 to this issue.

  A flaw in date handling was found in Mailman version 2.1.4 through 2.1.6.
  An attacker could send a carefully crafted email message to a mailing list
  run by Mailman which would cause the Mailman server to crash.
  (CVE-2005-4153).

  Users of Mailman should upgrade to this updated package, which contains
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0204.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3573", "CVE-2005-4153");
script_summary(english: "Check for the version of the mailman packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mailman-2.1.5.1-25.rhel3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5.1-34.rhel4.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
