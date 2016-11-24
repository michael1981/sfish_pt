
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41008);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1451: freeradius");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1451");
 script_set_attribute(attribute: "description", value: '
  Updated freeradius packages that fix a security issue are now available for
  Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  FreeRADIUS is a high-performance and highly configurable free Remote
  Authentication Dial In User Service (RADIUS) server, designed to allow
  centralized authentication and authorization for a network.

  An input validation flaw was discovered in the way FreeRADIUS decoded
  specific RADIUS attributes from RADIUS packets. A remote attacker could use
  this flaw to crash the RADIUS daemon (radiusd) via a specially-crafted
  RADIUS packet. (CVE-2009-3111)

  Users of FreeRADIUS are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing the
  update, radiusd will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1451.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-3111");
script_summary(english: "Check for the version of the freeradius packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"freeradius-1.1.3-1.5.el5_4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-mysql-1.1.3-1.5.el5_4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-postgresql-1.1.3-1.5.el5_4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-unixODBC-1.1.3-1.5.el5_4", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-1.1.3-1.5.el5_4", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-mysql-1.1.3-1.5.el5_4", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-postgresql-1.1.3-1.5.el5_4", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeradius-unixODBC-1.1.3-1.5.el5_4", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
