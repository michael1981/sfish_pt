
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25404);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0386: mutt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0386");
 script_set_attribute(attribute: "description", value: '
  An updated mutt package that fixes several security bugs is now available
  for
  Red Hat Enterprise Linux 3, 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mutt is a text-mode mail user agent.

  A flaw was found in the way Mutt used temporary files on NFS file systems.
  Due to an implementation issue in the NFS protocol, Mutt was not able to
  exclusively open a new file. A local attacker could conduct a
  time-dependent attack and possibly gain access to e-mail attachments opened
  by a victim. (CVE-2006-5297)

  A flaw was found in the way Mutt processed certain APOP authentication
  requests. By sending certain responses when mutt attempted to authenticate
  against an APOP server, a remote attacker could potentially acquire certain
  portions of a user\'s authentication credentials. (CVE-2007-1558)

  A flaw was found in the way Mutt handled certain characters in gecos fields
  which could lead to a buffer overflow. The gecos field is an entry in the
  password database typically used to record general information about the
  user. A local attacker could give themselves a carefully crafted "Real
  Name" which could execute arbitrary code if a victim uses Mutt and expands
  the attackers alias. (CVE-2007-2683)

  All users of mutt should upgrade to this updated package, which
  contains a backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0386.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-5297", "CVE-2007-1558", "CVE-2007-2683");
script_summary(english: "Check for the version of the mutt packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mutt-1.4.2.2-3.0.2.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mutt-1.4.1-5.el3", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mutt-1.4.1-12.0.3.el4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
