
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12452);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-019: mailman");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-019");
 script_set_attribute(attribute: "description", value: '
  Updated mailman packages that close a DoS vulnerability present in mailman
  versions prior to version 2.1 are now available.

  Mailman is a mailing list manager.

  Matthew Galgoci of Red Hat discovered a Denial of Service (DoS)
  vulnerability in versions of Mailman prior to 2.1. An attacker could send
  a carefully-crafted message causing mailman to crash. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0991 to this issue.

  Users of Mailman are advised to upgrade to the erratum packages, which
  include a backported security fix and are not vulnerable to this issue.

  Red Hat would like to thank Barry Warsaw for providing a patch for this
  issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-019.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0991");
script_summary(english: "Check for the version of the mailman packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mailman-2.0.13-5", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
