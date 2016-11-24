
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17339);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-152: postfix");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-152");
 script_set_attribute(attribute: "description", value: '
  Updated postfix packages that include a security fix and two other bug
  fixes are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team

  Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL),
  and TLS.

  A flaw was found in the ipv6 patch used with Postfix. When the file
  /proc/net/if_inet6 is not available and permit_mx_backup is enabled in
  smtpd_recipient_restrictions, this flaw could allow remote attackers to
  bypass e-mail restrictions and perform mail relaying by sending mail to an
  IPv6 hostname. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0337 to this issue.

  These updated packages also fix the following problems:

  - wrong permissions on doc directory
  - segfault when gethostbyname or gethostbyaddr fails

  All users of postfix should upgrade to these updated packages, which
  contain patches which resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-152.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0337");
script_summary(english: "Check for the version of the postfix packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"postfix-2.1.5-4.2.RHEL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postfix-pflogsumm-2.1.5-4.2.RHEL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
