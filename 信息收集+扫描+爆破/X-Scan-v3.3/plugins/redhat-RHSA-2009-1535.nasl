
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42312);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1535: pidgin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1535");
 script_set_attribute(attribute: "description", value: '
  An updated pidgin package that fixes several security issues is now
  available for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  An invalid pointer dereference bug was found in the way the Pidgin OSCAR
  protocol implementation processed lists of contacts. A remote attacker
  could send a specially-crafted contact list to a user running Pidgin,
  causing Pidgin to crash. (CVE-2009-3615)

  A NULL pointer dereference flaw was found in the way the Pidgin IRC
  protocol plug-in handles IRC topics. A malicious IRC server could send a
  specially-crafted IRC TOPIC message, which once received by Pidgin, would
  lead to a denial of service (Pidgin crash). (CVE-2009-2703)

  A NULL pointer dereference flaw was found in the way the Pidgin MSN
  protocol plug-in handles improper MSNSLP invitations. A remote attacker
  could send a specially-crafted MSNSLP invitation request, which once
  accepted by a valid Pidgin user, would lead to a denial of service (Pidgin
  crash). (CVE-2009-3083)

  All Pidgin users should upgrade to this updated package, which contains
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1535.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2703", "CVE-2009-3083", "CVE-2009-3615");
script_summary(english: "Check for the version of the pidgin packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pidgin-1.5.1-6.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
