
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(23676);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0719: nss_ldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0719");
 script_set_attribute(attribute: "description", value: '
  Updated nss_ldap packages that fix a security flaw are now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  nss_ldap is a set of C library extensions that allow X.500 and LDAP
  directory servers to be used as primary sources for aliases, ethers,
  groups, hosts, networks, protocols, users, RPCs, services, and shadow
  passwords.

  A flaw was found in the way nss_ldap handled a PasswordPolicyResponse
  control sent by an LDAP server. If an LDAP server responded to an
  authentication request with a PasswordPolicyResponse control, it was
  possible for an application using nss_ldap to improperly authenticate
  certain users. (CVE-2006-5170)

  This flaw was only exploitable within applications which did not properly
  process nss_ldap error messages. Only xscreensaver is currently known to
  exhibit this behavior.

  All users of nss_ldap should upgrade to these updated packages, which
  contain a backported patch that resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0719.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-5170");
script_summary(english: "Check for the version of the nss_ldap packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"nss_ldap-226-17", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
