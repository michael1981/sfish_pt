
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21638);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0541: dia");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0541");
 script_set_attribute(attribute: "description", value: '
  Updated Dia packages that fix several buffer overflow bugs are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Dia drawing program is designed to draw various types of diagrams.

  Several format string flaws were found in the way dia displays certain
  messages. If an attacker is able to trick a Dia user into opening a
  carefully crafted file, it may be possible to execute arbitrary code as the
  user running Dia. (CVE-2006-2453, CVE-2006-2480)

  Users of Dia should update to these erratum packages, which contain
  backported patches and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0541.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-2453", "CVE-2006-2480");
script_summary(english: "Check for the version of the dia packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dia-0.94-5.7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
