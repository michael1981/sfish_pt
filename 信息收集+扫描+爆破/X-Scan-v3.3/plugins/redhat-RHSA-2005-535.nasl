
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18594);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-535: sudo");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-535");
 script_set_attribute(attribute: "description", value: '
  An updated sudo package is available that fixes a race condition in sudo\'s
  pathname validation.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The sudo (superuser do) utility allows system administrators to give
  certain users the ability to run commands as root with logging.

  A race condition bug was found in the way sudo handles pathnames. It is
  possible that a local user with limited sudo access could create
  a race condition that would allow the execution of arbitrary commands as
  the root user. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-1993 to this issue.

  Users of sudo should update to this updated package, which contains a
  backported patch and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-535.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1993");
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

if ( rpm_check( reference:"sudo-1.6.5p2-1.7x.2", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.7p5-1.1", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.7p5-30.1.1", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
