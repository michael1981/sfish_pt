
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39529);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1127: kdelibs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1127");
 script_set_attribute(attribute: "description", value: '
  Updated kdelibs packages that fix multiple security issues are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The kdelibs packages provide libraries for the K Desktop Environment (KDE).

  A flaw was found in the way the KDE CSS parser handled content for the
  CSS "style" attribute. A remote attacker could create a specially-crafted
  CSS equipped HTML page, which once visited by an unsuspecting user, could
  cause a denial of service (Konqueror crash) or, potentially, execute
  arbitrary code with the privileges of the user running Konqueror.
  (CVE-2009-1698)

  A flaw was found in the way the KDE HTML parser handled content for the
  HTML "head" element. A remote attacker could create a specially-crafted
  HTML page, which once visited by an unsuspecting user, could cause a denial
  of service (Konqueror crash) or, potentially, execute arbitrary code with
  the privileges of the user running Konqueror. (CVE-2009-1690)

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way the KDE JavaScript garbage collector handled memory
  allocation requests. A remote attacker could create a specially-crafted
  HTML page, which once visited by an unsuspecting user, could cause a denial
  of service (Konqueror crash) or, potentially, execute arbitrary code with
  the privileges of the user running Konqueror. (CVE-2009-1687)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The desktop must be restarted (log out,
  then log back in) for this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1127.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1687", "CVE-2009-1690", "CVE-2009-1698");
script_summary(english: "Check for the version of the kdelibs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdelibs-3.5.4-22.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-apidocs-3.5.4-22.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.5.4-22.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.3.1-14.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-14.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.3.1-14.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-14.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.5.4-22.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-apidocs-3.5.4-22.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.5.4-22.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
