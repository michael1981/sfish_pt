
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12342);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2002-294: fetchmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-294");
 script_set_attribute(attribute: "description", value: '
  Updated Fetchmail packages are available for Red Hat Linux Advanced Server
  which close a remotely-exploitable vulnerability in unpatched versions of
  Fetchmail prior to 6.2.0.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation

  Fetchmail is a remote mail retrieval and forwarding utility intended for
  use over on-demand TCP/IP links such as SLIP and PPP connections. A bug
  has been found in the header parsing code in versions of Fetchmail prior
  to 6.2.0.

  The bug allows a remote attacker to crash Fetchmail and potentially execute
  arbitrary code by sending a carefully crafted email which is parsed by
  Fetchmail.

  All users of Fetchmail are advised to upgrade to the errata packages
  containing a backported fix which corrects this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-294.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1365");
script_summary(english: "Check for the version of the fetchmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"fetchmail-5.9.0-21.7.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.0-21.7.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
