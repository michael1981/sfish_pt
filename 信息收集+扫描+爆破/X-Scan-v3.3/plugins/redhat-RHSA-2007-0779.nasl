
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28241);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0779: mailman");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0779");
 script_set_attribute(attribute: "description", value: '
  Updated mailman packages that fix a security issue and various bugs are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Mailman is a program used to help manage email discussion lists.

  A flaw was found in Mailman. A remote attacker could spoof messages in
  the error log, and possibly trick the administrator into visiting malicious
  URLs via a carriage return/line feed sequence in the URI. (CVE-2006-4624)

  As well, these updated packages fix the following bugs:

  * canceling a subscription on the confirm subscription request page
  caused mailman to crash.

  * editing the sender filter caused all spam filter rules to be deleted.

  * the migrate-fhs script was not included.

  * the mailman init script returned a zero (success) exit code even when
  an incorrect command was given. For example, the "mailman foo" command
  returned a zero exit code. In these updated packages the mailmain init
  script returns the correct exit codes.

  Users of Mailman are advised to upgrade to these updated packages, which
  resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0779.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4624");
script_summary(english: "Check for the version of the mailman packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mailman-2.1.5.1-34.rhel4.6", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
