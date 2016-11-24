
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25610);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0556: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0556");
 script_set_attribute(attribute: "description", value: '
  Updated Apache httpd packages that correct three security issues are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular Web server.

  The Apache HTTP Server did not verify that a process was an Apache child
  process before sending it signals. A local attacker with the ability to run
  scripts on the Apache HTTP Server could manipulate the scoreboard and cause
  arbitrary processes to be terminated which could lead to a denial of
  service (CVE-2007-3304). This issue is not exploitable on Red Hat
  Enterprise Linux 5 if using the default SELinux targeted policy.

  A flaw was found in the Apache HTTP Server mod_status module. On sites
  where the server-status page is publicly accessible and ExtendedStatus is
  enabled this could lead to a cross-site scripting attack. On Red Hat
  Enterprise Linux the server-status page is not enabled by default and it is
  best practice to not make this publicly available. (CVE-2006-5752)

  A bug was found in the Apache HTTP Server mod_cache module. On sites where
  caching is enabled, a remote attacker could send a carefully crafted
  request that would cause the Apache child process handling that request to
  crash. This could lead to a denial of service if using a threaded
  Multi-Processing Module. (CVE-2007-1863)

  Users of httpd should upgrade to these updated packages, which contain
  backported patches to correct these issues. Users should restart Apache
  after installing this update.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0556.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-5752", "CVE-2007-1863", "CVE-2007-3304");
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

if ( rpm_check( reference:"httpd-2.2.3-7.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.2.3-7.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.2.3-7.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.2.3-7.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
