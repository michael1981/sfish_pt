
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42064);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1484: postgresql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1484");
 script_set_attribute(attribute: "description", value: '
  Updated postgresql packages that fix two security issues are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PostgreSQL is an advanced object-relational database management system
  (DBMS).

  It was discovered that the upstream patch for CVE-2007-6600 included in the
  Red Hat Security Advisory RHSA-2008:0038 did not include protection against
  misuse of the RESET ROLE and RESET SESSION AUTHORIZATION commands. An
  authenticated user could use this flaw to install malicious code that would
  later execute with superuser privileges. (CVE-2009-3230)

  A flaw was found in the way PostgreSQL handled encoding conversion. A
  remote, authenticated user could trigger an encoding conversion failure,
  possibly leading to a temporary denial of service. Note: To exploit this
  issue, a locale and client encoding for which specific messages fail to
  translate must be selected (the availability of these is determined by an
  administrator-defined locale setting). (CVE-2009-0922)

  Note: For Red Hat Enterprise Linux 4, this update upgrades PostgreSQL to
  version 7.4.26. For Red Hat Enterprise Linux 5, this update upgrades
  PostgreSQL to version 8.1.18. Refer to the PostgreSQL Release Notes for a
  list of changes:

  http://www.postgresql.org/docs/7.4/static/release.html
  http://www.postgresql.org/docs/8.1/static/release.html

  All PostgreSQL users should upgrade to these updated packages, which
  resolve these issues. If the postgresql service is running, it will be
  automatically restarted after installing this update.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1484.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0922", "CVE-2009-3230");
script_summary(english: "Check for the version of the postgresql packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"postgresql-8.1.18-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-8.1.18-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.1.18-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-8.1.18-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-8.1.18-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-8.1.18-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-8.1.18-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-8.1.18-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-8.1.18-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-8.1.18-2.el5_4.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.4.26-1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-jdbc-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.4.26-1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-8.1.18-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-8.1.18-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.1.18-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-8.1.18-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-8.1.18-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-8.1.18-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-python-8.1.18-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-8.1.18-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-tcl-8.1.18-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-8.1.18-2.el5_4.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
