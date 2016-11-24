
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21286);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0267: ipsec");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0267");
 script_set_attribute(attribute: "description", value: '
  Updated ipsec-tools packages that fix a bug in racoon are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The ipsec-tools package is used in conjunction with the IPsec functionality
  in the linux kernel and includes racoon, an IKEv1 keying daemon.

  A denial of service flaw was found in the ipsec-tools racoon daemon. If a
  victim\'s machine has racoon configured in a non-recommended insecure
  manner, it is possible for a remote attacker to crash the racoon daemon.
  (CVE-2005-3732)

  Users of ipsec-tools should upgrade to these updated packages, which contain
  backported patches, and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0267.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3732");
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

if ( rpm_check( reference:"ipsec-tools-0.2.5-0.7.rhel3.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.3.3-6.rhel4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
