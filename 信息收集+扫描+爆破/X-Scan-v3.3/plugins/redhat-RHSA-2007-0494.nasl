
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25522);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0494: kdebase");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0494");
 script_set_attribute(attribute: "description", value: '
  Updated kdebase packages that resolve an interaction security issue with
  Adobe Flash Player are now available.

  This update has been rated as having important security impact by the Red Hat
  Security Response Team.

  The kdebase packages provide the core applications for KDE, the K Desktop
  Environment. These core packages include Konqueror, the web browser and
  file manager.

  A problem with the interaction between the Flash Player and the Konqueror
  web browser was found. The problem could lead to key presses leaking to the
  Flash Player applet instead of the browser (CVE-2007-2022).

  Users of Konqueror who have installed the Adobe Flash Player plugin should
  upgrade to these updated packages, which contain a patch provided by Dirk
  M  ller that protects against this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0494.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2022");
script_summary(english: "Check for the version of the kdebase packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdebase-3.5.4-13.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.5.4-13.6.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-3.1.3-5.16", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.1.3-5.16", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-3.3.1-5.19.rhel4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.3.1-5.19.rhel4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
