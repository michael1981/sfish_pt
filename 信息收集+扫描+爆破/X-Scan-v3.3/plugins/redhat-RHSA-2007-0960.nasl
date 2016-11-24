
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27036);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0960: hpijs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0960");
 script_set_attribute(attribute: "description", value: '
  An updated hplip package to correct a security flaw is now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The hplip (Hewlett-Packard Linux Imaging and Printing Project) package
  provides drivers for HP printers and multi-function peripherals.

  Kees Cook discovered a flaw in the way the hplip hpssd daemon handled user
  input. A local attacker could send a specially crafted request to the hpssd
  daemon, possibly allowing them to run arbitrary commands as the root user.
  (CVE-2007-5208). On Red Hat Enterprise Linux 5, the SELinux targeted
  policy for hpssd which is enabled by default, blocks the ability to exploit
  this issue to run arbitrary code.

  Users of hplip are advised to upgrade to this updated package, which
  contains backported patches to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0960.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5208");
script_summary(english: "Check for the version of the hpijs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"hpijs-1.6.7-4.1.el5_0.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hplip-1.6.7-4.1.el5_0.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsane-hpaio-1.6.7-4.1.el5_0.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
