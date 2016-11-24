
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20886);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0207: gnutls");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0207");
 script_set_attribute(attribute: "description", value: '
  Updated gnutls packages that fix a security issue are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The GNU TLS Library provides support for cryptographic algorithms and
  protocols such as TLS. GNU TLS includes Libtasn1, a library developed for
  ASN.1 structures management that includes DER encoding and decoding.

  Several flaws were found in the way libtasn1 decodes DER. An attacker
  could create a carefully crafted invalid X.509 certificate in such a way
  that could trigger this flaw if parsed by an application that uses GNU TLS.
  This could lead to a denial of service (application crash). It is not
  certain if this issue could be escalated to allow arbitrary code execution.
  The Common Vulnerabilities and Exposures project assigned the name
  CVE-2006-0645 to this issue.

  In Red Hat Enterprise Linux 4, the GNU TLS library is only used by the
  Evolution client when connecting to an Exchange server or when publishing
  calendar information to a WebDAV server.

  Users are advised to upgrade to these updated packages, which contain a
  backported patch from the GNU TLS maintainers to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0207.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0645");
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

if ( rpm_check( reference:"gnutls-1.0.20-3.2.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-devel-1.0.20-3.2.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
