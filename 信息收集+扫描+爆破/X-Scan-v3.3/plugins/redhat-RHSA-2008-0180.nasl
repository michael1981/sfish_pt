
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31617);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0180: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0180");
 script_set_attribute(attribute: "description", value: '
  Updated krb5 packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other through use of symmetric encryption
  and a trusted third party, the KDC.

  A flaw was found in the way the MIT Kerberos Authentication Service and Key
  Distribution Center server (krb5kdc) handled Kerberos v4 protocol packets.
  An unauthenticated remote attacker could use this flaw to crash the
  krb5kdc daemon, disclose portions of its memory, or possibly execute
  arbitrary code using malformed or truncated Kerberos v4 protocol
  requests. (CVE-2008-0062, CVE-2008-0063)

  This issue only affected krb5kdc with Kerberos v4 protocol compatibility
  enabled, which is the default setting on Red Hat Enterprise Linux 4.
  Kerberos v4 protocol support can be disabled by adding "v4_mode=none"
  (without the quotes) to the "[kdcdefaults]" section of
  /var/kerberos/krb5kdc/kdc.conf.

  Red Hat would like to thank MIT for reporting these issues.

  A double-free flaw was discovered in the GSSAPI library used by MIT
  Kerberos. This flaw could possibly cause a crash of the application using
  the GSSAPI library. (CVE-2007-5971)

  All krb5 users are advised to update to these erratum packages which
  contain backported fixes to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0180.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063");
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

if ( rpm_check( reference:"krb5-devel-1.3.4-54.el4_6.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.3.4-54.el4_6.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.4-54.el4_6.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.4-54.el4_6.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
