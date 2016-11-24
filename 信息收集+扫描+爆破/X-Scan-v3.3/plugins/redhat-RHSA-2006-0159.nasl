
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20398);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0159: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0159");
 script_set_attribute(attribute: "description", value: '
  Updated Apache httpd packages that correct three security issues are now
  available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular and freely-available Web server.

  A memory leak in the worker MPM could allow remote attackers to cause a
  denial of service (memory consumption) via aborted connections, which
  prevents the memory for the transaction pool from being reused for other
  connections. The Common Vulnerabilities and Exposures project assigned the
  name CVE-2005-2970 to this issue. This vulnerability only affects users
  who are using the non-default worker MPM.

  A flaw in mod_imap when using the Referer directive with image maps was
  discovered. With certain site configurations, a remote attacker could
  perform a cross-site scripting attack if a victim can be forced to visit a
  malicious URL using certain web browsers. (CVE-2005-3352)

  A NULL pointer dereference flaw in mod_ssl was discovered affecting server
  configurations where an SSL virtual host is configured with access control
  and a custom 400 error document. A remote attacker could send a carefully
  crafted request to trigger this issue which would lead to a crash. This
  crash would only be a denial of service if using the non-default worker
  MPM. (CVE-2005-3357)

  Users of httpd should update to these erratum packages which contain
  backported patches to correct these issues along with some additional bugs.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0159.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2970", "CVE-2005-3352", "CVE-2005-3357");
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

if ( rpm_check( reference:"httpd-2.0.46-56.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-56.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-56.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-2.0.52-22.ent", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.52-22.ent", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.0.52-22.ent", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-suexec-2.0.52-22.ent", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.52-22.ent", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
