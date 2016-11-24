
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18407);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-430: gnutls");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-430");
 script_set_attribute(attribute: "description", value: '
  Updated GnuTLS packages that fix a remote denial of service
  vulnerability are available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The GnuTLS library implements Secure Sockets Layer (SSL v3) and Transport
  Layer Security (TLS v1) protocols.

  A denial of service bug was found in the GnuTLS library versions prior to
  1.0.25. A remote attacker could perform a carefully crafted TLS handshake
  against a service that uses the GnuTLS library causing the service to
  crash. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2005-1431 to this issue.

  All users of GnuTLS are advised to upgrade to these updated packages and to
  restart any services which use GnuTLS.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-430.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1431");
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

if ( rpm_check( reference:"gnutls-1.0.20-3.2.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-devel-1.0.20-3.2.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
