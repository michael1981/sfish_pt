
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25727);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0675: perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0675");
 script_set_attribute(attribute: "description", value: '
  An updated perl-Net-DNS package that corrects a security issue is now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Net::DNS is a collection of Perl modules that act as a Domain Name System
  (DNS) resolver.

  A flaw was found in the way Net::DNS generated the ID field in a DNS query.
  This predictable ID field could be used by a remote attacker to return
  invalid DNS data. (CVE-2007-3377)

  Users of Net::DNS should upgrade to this updated package, which contains
  backported patches to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0675.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3377");
script_summary(english: "Check for the version of the perl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-Net-DNS-0.48-2.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
