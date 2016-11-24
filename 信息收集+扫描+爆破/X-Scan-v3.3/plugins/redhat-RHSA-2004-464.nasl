
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14740);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-464: gmc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-464");
 script_set_attribute(attribute: "description", value: '
  An updated mc package that resolves several shell escape security issues is
  now available.

  [Updated 5 January 2005]
  Packages have been updated to include the gmc and mcserv packages which
  were
  left out of the initial errata.

  Midnight Commander (mc) is a visual shell much like a file manager.

  Shell escape bugs have been discovered in several of the mc vfs backend
  scripts. An attacker who is able to influence a victim to open a
  specially-crafted URI using mc could execute arbitrary commands as the
  victim. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has
  assigned the name CAN-2004-0494 to this issue.

  Users of mc should upgrade to this updated package which contains
  backported patches and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-464.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0494");
script_summary(english: "Check for the version of the gmc packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gmc-4.5.51-36.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mc-4.5.51-36.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mcserv-4.5.51-36.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
