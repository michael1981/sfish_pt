
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14737);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-449: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-449");
 script_set_attribute(attribute: "description", value: '
  Updated cups packages that fix a denial of service vulnerability are now
  available.

  The Common UNIX Printing System (CUPS) is a print spooler.

  Alvaro Martinez Echevarria reported a bug in the CUPS Internet Printing
  Protocol (IPP) implementation in versions of CUPS prior to 1.1.21. An
  attacker could send a carefully crafted UDP packet to the IPP port which
  could cause CUPS to stop listening to the port and result in a denial of
  service. In order to exploit this bug, an attacker would need to have the
  ability to send a UDP packet to the IPP port (by default 631). The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0558 to this issue.

  All users of cups should upgrade to these updated packages, which contain a
  backported patch as well as a fix for a non-exploitable off-by-one bug.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-449.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0558");
script_summary(english: "Check for the version of the cups packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.1.17-13.3.13", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.13", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.13", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
