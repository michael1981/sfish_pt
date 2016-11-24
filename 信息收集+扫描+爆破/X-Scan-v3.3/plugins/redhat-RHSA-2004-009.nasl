
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12449);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-009: elm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-009");
 script_set_attribute(attribute: "description", value: '
  Updated elm packages are now available that fix a buffer overflow
  vulnerability in the \'frm\' command.

  Elm is a terminal mode email user agent. The frm command is provided as
  part of the Elm packages and gives a summary list of the sender and subject
  of selected messages in a mailbox or folder.

  A buffer overflow vulnerability was found in the frm command. An attacker
  could create a message with an overly long Subject line such that when the
  frm command is run by a victim arbitrary code is executed. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0966 to this issue.

  Users of the frm command should update to these erratum packages, which
  contain a backported security patch that corrects this issue.

  Red Hat would like to thank Paul Rubin for discovering and disclosing this
  issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-009.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0966");
script_summary(english: "Check for the version of the elm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"elm-2.5.6-4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
