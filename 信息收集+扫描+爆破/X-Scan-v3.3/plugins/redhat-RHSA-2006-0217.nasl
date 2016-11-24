
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20966);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0217: metamail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0217");
 script_set_attribute(attribute: "description", value: '
  An updated metamail package that fixes a buffer overflow vulnerability for
  Red Hat Enterprise Linux 2.1 is now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Metamail is a system for handling multimedia mail.

  A buffer overflow bug was found in the way Metamail processes certain mail
  messages. An attacker could create a carefully-crafted message such that
  when it is opened by a victim and parsed through Metamail, it runs
  arbitrary code as the victim. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) assigned the name CVE-2006-0709 to this issue.

  Users of Metamail should upgrade to this updated package, which contains a
  backported patch that is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0217.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0709");
script_summary(english: "Check for the version of the metamail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"metamail-2.7-30", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
