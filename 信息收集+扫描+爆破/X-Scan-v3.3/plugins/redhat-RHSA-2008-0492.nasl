
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32429);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0492: gnutls");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0492");
 script_set_attribute(attribute: "description", value: '
  Updated gnutls packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The GnuTLS Library provides support for cryptographic algorithms and
  protocols such as TLS. GnuTLS includes libtasn1, a library developed for
  ASN.1 structures management that includes DER encoding and decoding.

  Flaws were found in the way GnuTLS handles malicious client connections. A
  malicious remote client could send a specially crafted request to a service
  using GnuTLS that could cause the service to crash. (CVE-2008-1948,
  CVE-2008-1949, CVE-2008-1950)

  We believe it is possible to leverage the flaw CVE-2008-1948 to execute
  arbitrary code but have been unable to prove this at the time of releasing
  this advisory. Red Hat Enterprise Linux 4 does not ship with any
  applications directly affected by this flaw. Third-party software which
  runs on Red Hat Enterprise Linux 4 could, however, be affected by this
  vulnerability. Consequently, we have assigned it important severity.

  Users of GnuTLS are advised to upgrade to these updated packages, which
  contain a backported patch that corrects these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0492.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1948", "CVE-2008-1949", "CVE-2008-1950");
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

if ( rpm_check( reference:"gnutls-1.0.20-4.el4_6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-devel-1.0.20-4.el4_6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
