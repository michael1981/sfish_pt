
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12471);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-073: metamail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-073");
 script_set_attribute(attribute: "description", value: '
  Updated metamail packages that fix a number of vulnerabilities are now
  available.

  Metamail is a system for handling multimedia mail.

  Ulf Harnhammar discovered two format string bugs and two buffer overflow
  bugs in versions of Metamail up to and including 2.7. An attacker could
  create a carefully-crafted message such that when it is opened by a victim
  and parsed through Metamail, it runs arbitrary code as the victim. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the names CAN-2004-0104 (format strings) and CAN-2004-0105 (buffer
  overflows) to these issues.

  Users of Red Hat Enterprise Linux 2.1 are advised to upgrade to these
  erratum packages, which contain a backported security patch and are not
  vulnerable to these issues. Please note that Red Hat Enterprise Linux 3
  does not contain Metamail and is therefore not vulnerable to these issues.

  Red Hat would like to thank Ulf Harnhammar for the notification and patch
  for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-073.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0104", "CVE-2004-0105");
script_summary(english: "Check for the version of the metamail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"metamail-2.7-29", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
