
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38871);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1059: pidgin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1059");
 script_set_attribute(attribute: "description", value: '
  An updated pidgin package that fixes two security issues is now available
  for Red Hat Enterprise Linux 3.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  A buffer overflow flaw was found in the way Pidgin initiates file transfers
  when using the Extensible Messaging and Presence Protocol (XMPP). If a
  Pidgin client initiates a file transfer, and the remote target sends a
  malformed response, it could cause Pidgin to crash or, potentially, execute
  arbitrary code with the permissions of the user running Pidgin. This flaw
  only affects accounts using XMPP, such as Jabber and Google Talk.
  (CVE-2009-1373)

  It was discovered that on 32-bit platforms, the Red Hat Security Advisory
  RHSA-2008:0584 provided an incomplete fix for the integer overflow flaw
  affecting Pidgin\'s MSN protocol handler. If a Pidgin client receives a
  specially-crafted MSN message, it may be possible to execute arbitrary code
  with the permissions of the user running Pidgin. (CVE-2009-1376)

  Note: By default, when using an MSN account, only users on your buddy list
  can send you messages. This prevents arbitrary MSN users from exploiting
  this flaw.

  All Pidgin users should upgrade to this update package, which contains
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1059.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1373", "CVE-2009-1376");
script_summary(english: "Check for the version of the pidgin packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pidgin-1.5.1-3.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
