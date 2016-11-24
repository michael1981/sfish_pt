
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12431);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-315: quagga");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-315");
 script_set_attribute(attribute: "description", value: '
  Updated Quagga packages that close a locally-exploitable denial of service
  vulnerability are now available.

  Quagga is an open source implementation of TCP/IP routing software.

  Herbert Xu reported that Quagga can accept spoofed messages sent on the
  kernel netlink interface by other users on the local machine. This could
  lead to a local denial of service attack. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2003-0858 to
  this issue.

  Users of Quagga should upgrade to these erratum packages, which contain a
  patch that checks that netlink messages actually came from the kernel.
  This erratum also includes quagga-devel and quagga-contrib packages which
  were not originally shipped with Red Hat Enterprise Linux 3.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-315.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0858");
script_summary(english: "Check for the version of the quagga packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"quagga-0.96.2-8.3E", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"quagga-contrib-0.96.2-8.3E", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"quagga-devel-0.96.2-8.3E", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
