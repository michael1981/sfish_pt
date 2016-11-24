
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39527);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1124: net");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1124");
 script_set_attribute(attribute: "description", value: '
  Updated net-snmp packages that fix a security issue are now available for
  Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Simple Network Management Protocol (SNMP) is a protocol used for
  network management.

  A divide-by-zero flaw was discovered in the snmpd daemon. A remote attacker
  could issue a specially-crafted GETBULK request that could crash the snmpd
  daemon. (CVE-2009-1887)

  Note: An attacker must have read access to the SNMP server in order to
  exploit this flaw. In the default configuration, the community name
  "public" grants read-only access. In production deployments, it is
  recommended to change this default community name.

  All net-snmp users should upgrade to these updated packages, which contain
  a backported patch to correct this issue. After installing the update, the
  snmpd and snmptrapd daemons will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1124.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1887");
script_summary(english: "Check for the version of the net packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"net-snmp-5.0.9-2.30E.28", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.0.9-2.30E.28", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-libs-5.0.9-2.30E.28", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-perl-5.0.9-2.30E.28", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.0.9-2.30E.28", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
