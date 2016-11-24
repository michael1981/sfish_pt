
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17190);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-133: xemacs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-133");
 script_set_attribute(attribute: "description", value: '
  Updated XEmacs packages that fix a string format issue are now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  XEmacs is a powerful, customizable, self-documenting, modeless text editor.

  Max Vozeler discovered several format string vulnerabilities in the
  movemail utility of XEmacs. If a user connects to a malicious POP server,
  an attacker can execute arbitrary code as the user running xemacs. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-0100 to this issue.

  Users of XEmacs are advised to upgrade to these updated packages, which
  contain backported patches to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-133.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0100");
script_summary(english: "Check for the version of the xemacs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xemacs-21.4.15-10.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xemacs-common-21.4.15-10.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xemacs-el-21.4.15-10.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xemacs-info-21.4.15-10.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xemacs-nox-21.4.15-10.EL.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
