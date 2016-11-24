
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36031);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0362: NetworkManager");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0362");
 script_set_attribute(attribute: "description", value: '
  Updated NetworkManager packages that fix a security issue are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  NetworkManager is a network link manager that attempts to keep a wired or
  wireless network connection active at all times.

  An information disclosure flaw was found in NetworkManager\'s D-Bus
  interface. A local attacker could leverage this flaw to discover sensitive
  information, such as network connection passwords and pre-shared keys.
  (CVE-2009-0365)

  Red Hat would like to thank Ludwig Nussel for responsibly reporting this
  flaw.

  NetworkManager users should upgrade to these updated packages, which
  contain a backported patch that corrects this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0362.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0365");
script_summary(english: "Check for the version of the NetworkManager packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"NetworkManager-0.3.1-5.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"NetworkManager-gnome-0.3.1-5.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
