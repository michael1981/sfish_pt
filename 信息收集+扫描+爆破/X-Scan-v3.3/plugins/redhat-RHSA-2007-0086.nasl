
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24678);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0086: gnomemeeting");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0086");
 script_set_attribute(attribute: "description", value: '
  Updated gnomemeeting packages that fix a security issue are now available
  for Red Hat Enterprise Linux.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  GnomeMeeting is a tool to communicate with video and audio over the
  Internet.

  A format string flaw was found in the way GnomeMeeting processes certain
  messages. If a user is running GnomeMeeting, a remote attacker who can
  connect to GnomeMeeting could trigger this flaw and potentially execute
  arbitrary code with the privileges of the user. (CVE-2007-1007)

  Users of GnomeMeeting should upgrade to these updated packages which
  contain a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0086.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1007");
script_summary(english: "Check for the version of the gnomemeeting packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnomemeeting-0.96.0-5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnomemeeting-1.0.2-9", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
