
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40433);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1181: bind");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1181");
 script_set_attribute(attribute: "description", value: '
  Updated bind packages that fix a security issue and a bug are now available
  for Red Hat Enterprise Linux 3.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
  Name System (DNS) protocols. BIND includes a DNS server (named); a resolver
  library (routines for applications to use when interfacing with DNS); and
  tools for verifying that the DNS server is operating correctly.

  A flaw was found in the way BIND handles dynamic update message packets
  containing the "ANY" record type. A remote attacker could use this flaw to
  send a specially-crafted dynamic update packet that could cause named to
  exit with an assertion failure. (CVE-2009-0696)

  Note: even if named is not configured for dynamic updates, receiving such
  a specially-crafted dynamic update packet could still cause named to exit
  unexpectedly.

  This update also fixes the following bug:

  * the following message could have been logged: "internal_accept: fcntl()
  failed: Too many open files". With these updated packages, timeout queries
  are aborted in order to reduce the number of open UDP sockets, and when the
  accept() function returns an EMFILE error value, that situation is now
  handled gracefully, thus resolving the issue. (BZ#498164)

  All BIND users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing the
  update, the BIND daemon (named) will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1181.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0696");
script_summary(english: "Check for the version of the bind packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"bind-9.2.4-25.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-chroot-9.2.4-25.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.2.4-25.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-libs-9.2.4-25.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.2.4-25.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
