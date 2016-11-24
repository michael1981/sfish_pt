
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25604);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0384: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0384");
 script_set_attribute(attribute: "description", value: '
  Updated krb5 packages that fix several security flaws are now available for
  Red Hat Enterprise Linux 2.1 and 3.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other through use of symmetric encryption
  and a trusted third party, the KDC. kadmind is the KADM5 administration
  server.

  David Coffey discovered an uninitialized pointer free flaw in the RPC
  library used by kadmind. A remote unauthenticated attacker who can access
  kadmind could trigger this flaw and cause kadmind to crash or potentially
  execute arbitrary code as root. (CVE-2007-2442)

  David Coffey also discovered an overflow flaw in the RPC library used by
  kadmind. On Red Hat Enterprise Linux, exploitation of this flaw is limited
  to a denial of service. A remote unauthenticated attacker who can access
  kadmind could trigger this flaw and cause kadmind to crash. (CVE-2007-2443)

  A stack buffer overflow flaw was found in kadmind. An authenticated
  attacker who can access kadmind could trigger this flaw and potentially
  execute arbitrary code on the Kerberos server. (CVE-2007-2798)

  For Red Hat Enterprise Linux 2.1, several portability bugs which would lead
  to unexpected crashes on the ia64 platform have also been fixed.

  Users of krb5-server are advised to update to these erratum packages which
  contain backported fixes to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0384.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2798");
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

if ( rpm_check( reference:"krb5-devel-1.2.2-47", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-47", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-47", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-47", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.7-66", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-66", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-66", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-66", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
