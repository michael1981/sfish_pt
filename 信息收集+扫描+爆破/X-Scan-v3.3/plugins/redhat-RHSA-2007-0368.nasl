
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27828);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0368: arpwatch");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0368");
 script_set_attribute(attribute: "description", value: '
  Updated tcpdump packages that fix a security issue and functionality bugs
  are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Tcpdump is a command line tool for monitoring network traffic.

  Moritz Jodeit discovered a denial of service bug in the tcpdump IEEE 802.11
  processing code. If a certain link type was explicitly specified, an
  attacker could inject a carefully crafted frame onto the IEEE 802.11
  network that could crash a running tcpdump session. (CVE-2007-1218)

  An integer overflow flaw was found in tcpdump\'s BGP processing code. An
  attacker could execute arbitrary code with the privilege of the pcap user
  by injecting a crafted frame onto the network. (CVE-2007-3798)

  In addition, the following bugs have been addressed:

  * The arpwatch service initialization script would exit prematurely,
  returning an incorrect successful exit status and preventing the status
  command from running in case networking is not available.

  * Tcpdump would not drop root privileges completely when launched with the
  -C option. This might have been abused by an attacker to gain root
  privileges in case a security problem was found in tcpdump. Users of
  tcpdump are encouraged to specify meaningful arguments to the -Z option in
  case they want tcpdump to write files with privileges other than of the
  pcap user.

  Users of tcpdump are advised to upgrade to these erratum packages, which
  contain backported patches that correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0368.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1218", "CVE-2007-3798");
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

if ( rpm_check( reference:"arpwatch-2.1a13-18.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.9.4-11.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpcap-devel-0.9.4-11.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.9.4-11.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
