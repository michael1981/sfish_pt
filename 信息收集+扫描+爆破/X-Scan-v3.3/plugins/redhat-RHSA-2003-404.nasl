
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12441);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2003-404: lftp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-404");
 script_set_attribute(attribute: "description", value: '
  Updated lftp packages are now available that fix a buffer overflow
  security vulnerability.

  lftp is a command-line file transfer program supporting FTP and HTTP
  protocols.

  Ulf H  rnhammar discovered a buffer overflow bug in versions of lftp up to
  and including 2.6.9. An attacker could create a carefully crafted
  directory on a website such that, if a user connects to that directory
  using the lftp client and subsequently issues a \'ls\' or \'rels\' command, the
  attacker could execute arbitrary code on the users machine. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0963 to this issue.

  Users of lftp are advised to upgrade to these erratum packages, which
  contain a backported security patch and are not vulnerable to this issue.

  Red Hat would like to thank Ulf H  rnhammar for discovering and alerting us
  to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-404.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0963");
script_summary(english: "Check for the version of the lftp packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lftp-2.4.9-2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lftp-2.6.3-5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
