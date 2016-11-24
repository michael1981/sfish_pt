
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42065);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1485: rh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1485");
 script_set_attribute(attribute: "description", value: '
  Updated postgresql packages that fix a security issue are now available for
  Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PostgreSQL is an advanced object-relational database management system
  (DBMS).

  It was discovered that the upstream patch for CVE-2007-6600 included in the
  Red Hat Security Advisory RHSA-2008:0039 did not include protection against
  misuse of the RESET ROLE and RESET SESSION AUTHORIZATION commands. An
  authenticated user could use this flaw to install malicious code that would
  later execute with superuser privileges. (CVE-2009-3230)

  All PostgreSQL users should upgrade to these updated packages, which
  contain a backported patch to correct this issue. If you are running a
  PostgreSQL server, the postgresql service must be restarted for this update
  to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1485.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-3230");
script_summary(english: "Check for the version of the rh packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"rh-postgresql-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-contrib-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-devel-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-docs-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-jdbc-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-libs-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-pl-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-python-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-server-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-tcl-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rh-postgresql-test-7.3.21-2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
