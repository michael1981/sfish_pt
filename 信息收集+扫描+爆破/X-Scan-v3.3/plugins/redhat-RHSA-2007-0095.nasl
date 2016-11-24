
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24948);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2007-0095: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0095");
 script_set_attribute(attribute: "description", value: '
  Updated krb5 packages that fix a number of issues are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other through use of symmetric encryption
  and a trusted third party, the KDC.

  A flaw was found in the username handling of the MIT krb5 telnet daemon
  (telnetd). A remote attacker who can access the telnet port of a target
  machine could log in as root without requiring a password. (CVE-2007-0956)

  Note that the krb5 telnet daemon is not enabled by default in any version
  of Red Hat Enterprise Linux. In addition, the default firewall rules block
  remote access to the telnet port. This flaw does not affect the telnet
  daemon distributed in the telnet-server package.

  For users who have enabled the krb5 telnet daemon and have it accessible
  remotely, this update should be applied immediately.

  Whilst we are not aware at this time that the flaw is being actively
  exploited, we have confirmed that the flaw is very easily exploitable.

  This update also fixes two additional security issues:

  Buffer overflows were found which affect the Kerberos KDC and the kadmin
  server daemon. A remote attacker who can access the KDC could exploit this
  bug to run arbitrary code with the privileges of the KDC or kadmin server
  processes. (CVE-2007-0957)

  A double-free flaw was found in the GSSAPI library used by the kadmin
  server daemon. Red Hat Enterprise Linux 4 and 5 contain checks within
  glibc that detect double-free flaws. Therefore, on Red Hat Enterprise Linux
  4 and 5 successful exploitation of this issue can only lead to a denial of
  service. Applications which use this library in earlier releases of Red
  Hat Enterprise Linux may also be affected. (CVE-2007-1216)

  All users are advised to update to these erratum packages which contain a
  backported fix to correct these issues.

  Red Hat would like to thank MIT and iDefense for reporting these
  vulnerabilities.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0095.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-0956", "CVE-2007-0957", "CVE-2007-1216");
script_summary(english: "Check for the version of the krb packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"krb5-devel-1.5-23", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.5-23", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.5-23", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.5-23", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.2-44", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-44", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-44", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-44", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.7-61", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-61", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-61", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-61", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.3.4-46", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.3.4-46", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.4-46", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.4-46", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
