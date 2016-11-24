
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38945);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1075: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1075");
 script_set_attribute(attribute: "description", value: '
  Updated httpd packages that fix two security issues are now available for
  Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular and freely-available Web server.

  A flaw was found in the handling of compression structures between mod_ssl
  and OpenSSL. If too many connections were opened in a short period of time,
  all system memory and swap space would be consumed by httpd, negatively
  impacting other processes, or causing a system crash. (CVE-2008-1678)

  Note: The CVE-2008-1678 issue did not affect Red Hat Enterprise Linux 5
  prior to 5.3. The problem was introduced via the RHBA-2009:0181 errata in
  Red Hat Enterprise Linux 5.3, which upgraded OpenSSL to the newer 0.9.8e
  version.

  A flaw was found in the handling of the "Options" and "AllowOverride"
  directives. In configurations using the "AllowOverride" directive with
  certain "Options=" arguments, local users were not restricted from
  executing commands from a Server-Side-Include script as intended.
  (CVE-2009-1195)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Users must restart httpd for
  this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1075.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1678", "CVE-2009-1195");
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

if ( rpm_check( reference:"httpd-2.2.3-22.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.2.3-22.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.2.3-22.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.2.3-22.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-2.2.3-22.el5_3.1", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.2.3-22.el5_3.1", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.2.3-22.el5_3.1", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.2.3-22.el5_3.1", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
