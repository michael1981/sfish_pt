
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12364);
 script_version ("$Revision: 1.11 $");
 script_name(english: "RHSA-2003-052: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-052");
 script_set_attribute(attribute: "description", value: '
  Updated kerberos packages fix a number of vulnerabilities found in MIT
  Kerberos.

  Kerberos is a network authentication system. The MIT Kerberos team
  released an advisory describing a number of vulnerabilities that affect the
  kerberos packages shipped by Red Hat.

  An integer signedness error in the ASN.1 decoder before version 1.2.5
  allows remote attackers to cause a denial of service via a large unsigned
  data element length, which is later used as a negative value. The Common
  Vulnerabilities and Exposures project has assigned the name CAN-2002-0036
  to this issue.

  The Key Distribution Center (KDC) before version 1.2.5 allows remote,
  authenticated, attackers to cause a denial of service (crash) on KDCs
  within the same realm via a certain protocol request that:

  - causes a null pointer dereference (CAN-2003-0058).

  - causes the KDC to corrupt its heap (CAN-2003-0082).

  A vulnerability in Kerberos before version 1.2.3 allows users from
  one realm to impersonate users in other realms that have the same
  inter-realm keys (CAN-2003-0059).

  The MIT advisory for these issues also mentions format string
  vulnerabilities in the logging routines (CAN-2003-0060). Previous versions
  of the kerberos packages from Red Hat already contain fixes for this issue.

  Vulnerabilities have been found in the implementation of support for
  triple-DES keys in the implementation of the Kerberos IV authentication
  protocol included in MIT Kerberos (CAN-2003-0139).

  Vulnerabilities have been found in the Kerberos IV authentication protocol
  which allow an attacker with knowledge of a cross-realm key that is shared
  with another realm to impersonate any principal in that realm to any
  service in that realm. This vulnerability can only be closed by disabling
  cross-realm authentication in Kerberos IV (CAN-2003-0138).

  Vulnerabilities have been found in the RPC library used by the kadmin
  service in Kerberos 5. A faulty length check in the RPC library exposes
  kadmind to an integer overflow which can be used to crash kadmind
  (CAN-2003-0028).

  All users of Kerberos are advised to upgrade to these errata packages,
  which disable cross-realm authentication by default for Kerberos IV and
  which contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-052.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0036", "CVE-2003-0028", "CVE-2003-0058", "CVE-2003-0059", "CVE-2003-0072", "CVE-2003-0082", "CVE-2003-0138", "CVE-2003-0139", "CVE-2004-0772");
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

if ( rpm_check( reference:"krb5-devel-1.2.2-24", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-24", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-24", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-24", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
