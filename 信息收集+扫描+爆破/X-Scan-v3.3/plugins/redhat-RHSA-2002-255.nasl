
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12333);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2002-255: webalizer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-255");
 script_set_attribute(attribute: "description", value: '
  Updated Webalizer packages are available for Red Hat Linux Advanced Server
  2.1 which fix an obscure buffer overflow bug in the DNS resolver code.

  [Updated 13 Jan 2003]
  Added fixed packages for the Itanium (IA64) architecture.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Webalizer is a Web server log file analysis program which produces
  detailed usage reports in HTML format.

  A buffer overflow in Webalizer versions prior to 2.01-10, when configured
  to use reverse DNS lookups, may allow remote attackers to execute arbitrary
  code by connecting to the monitored Web server from an IP address that
  resolves to a long hostname.

  Users of Webalizer are advised to upgrade to these errata packages which
  contain Webalizer version 2.01-09 with backported security and bug fix
  patches.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-255.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0180");
script_summary(english: "Check for the version of the webalizer packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"webalizer-2.01_09-1.72", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
