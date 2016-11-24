
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39770);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1148: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1148");
 script_set_attribute(attribute: "description", value: '
  Updated httpd packages that fix two security issues are now available for
  Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular Web server.

  A denial of service flaw was found in the Apache mod_proxy module when it
  was used as a reverse proxy. A remote attacker could use this flaw to force
  a proxy process to consume large amounts of CPU time. (CVE-2009-1890)

  A denial of service flaw was found in the Apache mod_deflate module. This
  module continued to compress large files until compression was complete,
  even if the network connection that requested the content was closed before
  compression completed. This would cause mod_deflate to consume large
  amounts of CPU if mod_deflate was enabled for a large file. (CVE-2009-1891)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1148.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1890", "CVE-2009-1891");
script_summary(english: "Check for the version of the httpd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"httpd-2.2.3-22.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.2.3-22.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.2.3-22.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.2.3-22.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-2.2.3-22.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.2.3-22.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.2.3-22.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.2.3-22.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
