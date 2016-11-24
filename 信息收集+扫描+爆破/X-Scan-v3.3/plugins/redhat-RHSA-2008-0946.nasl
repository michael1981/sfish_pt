
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34467);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0946: ed");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0946");
 script_set_attribute(attribute: "description", value: '
  An updated ed package that fixes one security issue is now available for
  Red Hat Enterprise Linux 2.1, 3, 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  ed is a line-oriented text editor, used to create, display, and modify
  text files (both interactively and via shell scripts).

  A heap-based buffer overflow was discovered in the way ed, the GNU line
  editor, processed long file names. An attacker could create a file with a
  specially-crafted name that could possibly execute an arbitrary code when
  opened in the ed editor. (CVE-2008-3916)

  Users of ed should upgrade to this updated package, which contains
  a backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0946.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3916");
script_summary(english: "Check for the version of the ed packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ed-0.2-39.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ed-0.2-21.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ed-0.2-33.30E.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ed-0.2-36.el4_7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
