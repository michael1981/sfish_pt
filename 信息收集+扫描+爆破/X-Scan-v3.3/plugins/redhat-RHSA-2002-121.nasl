
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12632);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2002-121: arpwatch");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-121");
 script_set_attribute(attribute: "description", value: '
  Updated tcpdump, libpcap, and arpwatch packages are available. These
  updates close a buffer overflow when handling NFS packets.

  tcpdump is a command-line tool for monitoring network traffic. Versions of
  tcpdump up to and including 3.6.2 have a buffer overflow that can be
  triggered when tracing the network by a bad NFS packet.

  We are not yet aware if this issue is fully exploitable; however, users of
  tcpdump are advised to upgrade to these errata packages which contain a
  patch for this issue.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2002-0380 to this issue. This issue was found by
  David Woodhouse of Red Hat.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-121.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0380");
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

if ( rpm_check( reference:"arpwatch-2.1a11-11.2.1AS.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.6.2-11.2.1AS.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-11.2.1AS.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
