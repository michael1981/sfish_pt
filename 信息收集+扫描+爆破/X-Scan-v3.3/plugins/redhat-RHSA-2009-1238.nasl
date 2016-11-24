
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40834);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1238: dnsmasq");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1238");
 script_set_attribute(attribute: "description", value: '
  An updated dnsmasq package that fixes two security issues is now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Dnsmasq is a lightweight and easy to configure DNS forwarder and DHCP
  server.

  Core Security Technologies discovered a heap overflow flaw in dnsmasq when
  the TFTP service is enabled (the "--enable-tftp" command line option, or by
  enabling "enable-tftp" in "/etc/dnsmasq.conf"). If the configured tftp-root
  is sufficiently long, and a remote user sends a request that sends a long
  file name, dnsmasq could crash or, possibly, execute arbitrary code with
  the privileges of the dnsmasq service (usually the unprivileged "nobody"
  user). (CVE-2009-2957)

  A NULL pointer dereference flaw was discovered in dnsmasq when the TFTP
  service is enabled. This flaw could allow a malicious TFTP client to crash
  the dnsmasq service. (CVE-2009-2958)

  Note: The default tftp-root is "/var/ftpd", which is short enough to make
  it difficult to exploit the CVE-2009-2957 issue; if a longer directory name
  is used, arbitrary code execution may be possible. As well, the dnsmasq
  package distributed by Red Hat does not have TFTP support enabled by
  default.

  All users of dnsmasq should upgrade to this updated package, which contains
  a backported patch to correct these issues. After installing the updated
  package, the dnsmasq service must be restarted for the update to take
  effect.


');
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1238.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2957", "CVE-2009-2958");
script_summary(english: "Check for the version of the dnsmasq packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dnsmasq-2.45-1.1.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dnsmasq-2.45-1.1.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
