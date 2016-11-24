
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12392);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2003-151: arpwatch");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-151");
 script_set_attribute(attribute: "description", value: '
  Updated tcpdump packages that fix an infinite loop vulnerability and drop
  privileges on startup are now available.

  Tcpdump is a command-line tool for monitoring network traffic.

  A vulnerability exists in tcpdump before 3.7.2 and is related to an
  inability to handle unknown RADIUS attributes properly. This vulnerability
  allows remote attackers to cause a denial of service (infinite loop).

  The Red Hat tcpdump packages advertise that, by default, tcpdump will drop
  privileges to user \'pcap\'. Due to a compilation error this did not
  happen, and tcpdump would run as root unless the \'-U\' flag was specified.

  Users of tcpdump are advised to upgrade to these errata packages, which
  contain a patch correcting the RADIUS issue and are compiled so that by
  default tcpdump will drop privileges to the \'pcap\' user.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-151.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0145", "CVE-2003-0194");
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

if ( rpm_check( reference:"arpwatch-2.1a11-12.2.1AS.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.6.2-12.2.1AS.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-12.2.1AS.4", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
