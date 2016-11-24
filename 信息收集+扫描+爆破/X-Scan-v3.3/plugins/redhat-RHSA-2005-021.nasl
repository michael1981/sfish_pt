
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18017);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-021: kdegraphics");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-021");
 script_set_attribute(attribute: "description", value: '
  Updated kdegraphics packages that resolve multiple security issues in kfax
  are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team

  The kdegraphics package contains graphics applications for the K Desktop
  Environment.

  During a source code audit, Chris Evans discovered a number of integer
  overflow bugs that affect libtiff. The kfax application contains a copy of
  the libtiff code used for parsing TIFF files and is therefore affected by
  these bugs. An attacker who has the ability to trick a user into opening a
  malicious TIFF file could cause kfax to crash or possibly execute arbitrary
  code. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CAN-2004-0886 and CAN-2004-0804 to these issues.

  Additionally, a number of buffer overflow bugs that affect libtiff have
  been found. The kfax application contains a copy of the libtiff code used
  for parsing TIFF files and is therefore affected by these bugs. An attacker
  who has the ability to trick a user into opening a malicious TIFF file
  could cause kfax to crash or possibly execute arbitrary code. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0803 to this issue.

  Users of kfax should upgrade to these updated packages, which contain
  backported patches and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-021.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-1307", "CVE-2004-1308");
script_summary(english: "Check for the version of the kdegraphics packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdegraphics-2.2.2-4.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-2.2.2-4.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-3.1.3-3.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-3.1.3-3.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
