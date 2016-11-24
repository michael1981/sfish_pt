
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33157);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0529: net");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0529");
 script_set_attribute(attribute: "description", value: '
  Updated net-snmp packages that fix a security issue are now available for
  Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Simple Network Management Protocol (SNMP) is a protocol used for
  network management.

  A flaw was found in the way Net-SNMP checked an SNMPv3 packet\'s Keyed-Hash
  Message Authentication Code (HMAC). An attacker could use this flaw to
  spoof an authenticated SNMPv3 packet. (CVE-2008-0960)

  A buffer overflow was found in the Perl bindings for Net-SNMP. This could
  be exploited if an attacker could convince an application using the
  Net-SNMP Perl module to connect to a malicious SNMP agent. (CVE-2008-2292)

  All users of net-snmp should upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0529.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0960", "CVE-2008-2292");
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

if ( rpm_check( reference:"net-snmp-5.3.1-24.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.3.1-24.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-libs-5.3.1-24.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-perl-5.3.1-24.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.3.1-24.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-5.0.9-2.30E.24", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.0.9-2.30E.24", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-libs-5.0.9-2.30E.24", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-perl-5.0.9-2.30E.24", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.0.9-2.30E.24", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-5.1.2-11.el4_6.11.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-devel-5.1.2-11.el4_6.11.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-libs-5.1.2-11.el4_6.11.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-perl-5.1.2-11.el4_6.11.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.1.2-11.el4_6.11.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
