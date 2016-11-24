
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25323);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0131: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0131");
 script_set_attribute(attribute: "description", value: '
  An updated squid package that fixes a security vulnerability is now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Squid is a high-performance proxy caching server for Web clients,
  supporting FTP, gopher, and HTTP data objects.

  A denial of service flaw was found in the way Squid processed the TRACE
  request method. It was possible for an attacker behind the Squid proxy
  to issue a malformed TRACE request, crashing the Squid daemon child
  process. As long as these requests were sent, it would prevent
  legitimate usage of the proxy server. (CVE-2007-1560)

  This flaw does not affect the version of Squid shipped in Red Hat
  Enterprise Linux 2.1, 3, or 4.

  Users of Squid should upgrade to this updated package, which contains a
  backported patch and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0131.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1560");
script_summary(english: "Check for the version of the squid packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squid-2.6.STABLE6-4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
