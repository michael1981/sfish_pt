
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25330);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0342: ipsec");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0342");
 script_set_attribute(attribute: "description", value: '
  Updated ipsec-tools packages that fix a denial of service flaw in racoon
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The ipsec-tools package is used in conjunction with the IPsec functionality
  in the linux kernel and includes racoon, an IKEv1 keying daemon.

  A denial of service flaw was found in the ipsec-tools racoon daemon. It was
  possible for a remote attacker, with knowledge of an existing ipsec tunnel,
  to terminate the ipsec connection between two machines. (CVE-2007-1841)

  Users of ipsec-tools should upgrade to these updated packages, which
  contain a backported patch that resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0342.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1841");
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

if ( rpm_check( reference:"ipsec-tools-0.6.5-8.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
