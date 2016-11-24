
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39413);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1102: cscope");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1102");
 script_set_attribute(attribute: "description", value: '
  An updated cscope package that fixes multiple security issues is now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  cscope is a mature, ncurses-based, C source-code tree browsing tool.

  Multiple buffer overflow flaws were found in cscope. An attacker could
  create a specially crafted source code file that could cause cscope to
  crash or, possibly, execute arbitrary code when browsed with cscope.
  (CVE-2004-2541, CVE-2009-0148)

  All users of cscope are advised to upgrade to this updated package, which
  contains backported patches to fix these issues. All running instances of
  cscope must be restarted for this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1102.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-2541", "CVE-2009-0148");
script_summary(english: "Check for the version of the cscope packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cscope-15.5-15.1.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cscope-15.5-15.1.el5_3.1", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
