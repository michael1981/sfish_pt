
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31159);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0110: compat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0110");
 script_set_attribute(attribute: "description", value: '
  Updated openldap packages that fix security issues are now available for
  Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenLDAP is an open source suite of Lightweight Directory Access Protocol
  (LDAP) applications and development tools. LDAP is a set of protocols for
  accessing directory services.

  These updated openldap packages fix a flaw in the way the OpenLDAP slapd
  daemon handled modify and modrdn requests with NOOP control on objects
  stored in a Berkeley DB (BDB) storage backend. An authenticated attacker
  with permission to perform modify or modrdn operations on such LDAP objects
  could cause slapd to crash. (CVE-2007-6698, CVE-2008-0658)

  Users of openldap should upgrade to these updated packages, which contain a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0110.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-6698", "CVE-2008-0658");
script_summary(english: "Check for the version of the compat packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"compat-openldap-2.3.27_2.2.29-8.el5_1.3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-2.3.27-8.el5_1.3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-clients-2.3.27-8.el5_1.3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-devel-2.3.27-8.el5_1.3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-2.3.27-8.el5_1.3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-sql-2.3.27-8.el5_1.3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"compat-openldap-2.1.30-8.el4_6.4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-2.2.13-8.el4_6.4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-clients-2.2.13-8.el4_6.4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-devel-2.2.13-8.el4_6.4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-2.2.13-8.el4_6.4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-sql-2.2.13-8.el4_6.4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
