
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36112);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0408: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0408");
 script_set_attribute(attribute: "description", value: '
  Updated krb5 packages that fix various security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other using symmetric encryption and a
  trusted third party, the Key Distribution Center (KDC). The Generic
  Security Service Application Program Interface (GSS-API) definition
  provides security services to callers (protocols) in a generic fashion. The
  Simple and Protected GSS-API Negotiation (SPNEGO) mechanism is used by
  GSS-API peers to choose from a common set of security mechanisms.

  An input validation flaw was found in the ASN.1 (Abstract Syntax Notation
  One) decoder used by MIT Kerberos. A remote attacker could use this flaw to
  crash a network service using the MIT Kerberos library, such as kadmind or
  krb5kdc, by causing it to dereference or free an uninitialized pointer.
  (CVE-2009-0846)

  Multiple input validation flaws were found in the MIT Kerberos GSS-API
  library\'s implementation of the SPNEGO mechanism. A remote attacker could
  use these flaws to crash any network service utilizing the MIT Kerberos
  GSS-API library to authenticate users or, possibly, leak portions of the
  service\'s memory. (CVE-2009-0844, CVE-2009-0845)

  All krb5 users should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running services using the
  MIT Kerberos libraries must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0408.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846");
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

if ( rpm_check( reference:"krb5-devel-1.6.1-31.el5_3.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.6.1-31.el5_3.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.6.1-31.el5_3.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.6.1-31.el5_3.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
