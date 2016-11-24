
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12447);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-005: kdepim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-005");
 script_set_attribute(attribute: "description", value: '
  Updated kdepim packages are now available that fix a local buffer overflow
  vulnerability.

  The K Desktop Environment (KDE) is a graphical desktop for the X Window
  System. The KDE Personal Information Management (kdepim) suite helps you to
  organize your mail, tasks, appointments, and contacts.

  The KDE team found a buffer overflow in the file information reader of
  VCF files. An attacker could construct a VCF file so that when it was
  opened by a victim it would execute arbitrary commands. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0988 to this issue.

  Users of kdepim are advised to upgrade to these erratum packages which
  contain a backported security patch that corrects this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-005.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0988");
script_summary(english: "Check for the version of the kdepim packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdepim-3.1.3-3.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdepim-devel-3.1.3-3.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
