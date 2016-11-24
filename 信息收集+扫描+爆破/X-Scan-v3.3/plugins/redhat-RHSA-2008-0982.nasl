
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34752);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0982: gnutls");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0982");
 script_set_attribute(attribute: "description", value: '
  Updated gnutls packages that fix a security issue are now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The GnuTLS library provides support for cryptographic algorithms and for
  protocols such as Transport Layer Security (TLS).

  Martin von Gagern discovered a flaw in the way GnuTLS verified certificate
  chains provided by a server. A malicious server could use this flaw to
  spoof its identity by tricking client applications using the GnuTLS library
  to trust invalid certificates. (CVE-2008-4989)

  Users of GnuTLS are advised to upgrade to these updated packages, which
  contain a backported patch that corrects this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0982.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-4989");
script_summary(english: "Check for the version of the gnutls packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnutls-1.4.1-3.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-devel-1.4.1-3.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-utils-1.4.1-3.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
