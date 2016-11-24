
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38819);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1036: ipsec");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1036");
 script_set_attribute(attribute: "description", value: '
  An updated ipsec-tools package that fixes multiple security issues is now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The ipsec-tools package is used in conjunction with the IPsec functionality
  in the Linux kernel and includes racoon, an IKEv1 keying daemon.

  A denial of service flaw was found in the ipsec-tools racoon daemon. An
  unauthenticated, remote attacker could trigger a NULL pointer dereference
  that could cause the racoon daemon to crash. (CVE-2009-1574)

  Multiple memory leak flaws were found in the ipsec-tools racoon daemon. If
  a remote attacker is able to make multiple connection attempts to the
  racoon daemon, it was possible to cause the racoon daemon to consume all
  available memory. (CVE-2009-1632)

  Users of ipsec-tools should upgrade to this updated package, which contains
  backported patches to correct these issues. Users must restart the racoon
  daemon for this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1036.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1574", "CVE-2009-1632");
script_summary(english: "Check for the version of the ipsec packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ipsec-tools-0.6.5-13.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.6.5-13.el5_3.1", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
