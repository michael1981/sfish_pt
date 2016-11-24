
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15532);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-604: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-604");
 script_set_attribute(attribute: "description", value: '
  An updated gaim package that fixes security issues, fixes various bugs, and
  includes various enhancements for Red Hat Enterprise Linux 3 is now
  avaliable.

  The gaim application is a multi-protocol instant messaging client.

  A buffer overflow has been discovered in the MSN protocol handler. When
  receiving unexpected sequence of MSNSLP messages, it is possible that an
  attacker could cause an internal buffer overflow, leading to a crash or
  possible code execution. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0891 to this issue.

  This updated gaim package also fixes multiple user interface, protocol, and
  error handling problems, including an ICQ communication encoding issue.

  Additionally, these updated packages have compiled gaim as a PIE (position
  independent executable) for added protection against future security
  vulnerabilities.

  All users of gaim should upgrade to this updated package, which includes
  various bug fixes, as well as a backported security patch.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-604.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0891");
script_summary(english: "Check for the version of the gaim packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gaim-1.0.1-1.RHEL3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
