
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18238);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-417: arpwatch");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-417");
 script_set_attribute(attribute: "description", value: '
  Updated tcpdump packages that fix several security issues are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  This updated package also adds support for output files larger than 2 GB.

  Tcpdump is a command-line tool for monitoring network traffic.

  Several denial of service bugs were found in the way tcpdump processes
  certain network packets. It is possible for an attacker to inject a
  carefully crafted packet onto the network, crashing a running tcpdump
  session. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CAN-2005-1278, CAN-2005-1279, and CAN-2005-1280 to
  these issues.

  The tcpdump utility can now write a file larger than 2 GB.

  Users of tcpdump are advised to upgrade to these erratum packages, which
  contain backported security patches and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-417.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1278", "CVE-2005-1279", "CVE-2005-1280");
script_summary(english: "Check for the version of the arpwatch packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"arpwatch-2.1a13-9.RHEL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.8.3-9.RHEL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.8.2-9.RHEL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
