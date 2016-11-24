
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19425);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-708: gpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-708");
 script_set_attribute(attribute: "description", value: '
  An updated gpdf package that fixes a security issue is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The gpdf package is an GNOME based viewer for Portable Document Format
  (PDF) files.

  Marcus Meissner reported a flaw in gpdf. An attacker could construct a
  carefully crafted PDF file that would cause gpdf to consume all available
  disk space in /tmp when opened. The Common Vulnerabilities and Exposures
  project assigned the name CAN-2005-2097 to this issue.

  Note that this issue does not affect the version of gpdf in Red Hat
  Enterprise Linux 3 or 2.1.

  Users of gpdf should upgrade to this updated package, which contains a
  backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-708.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2097");
script_summary(english: "Check for the version of the gpdf packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gpdf-2.8.2-4.4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
