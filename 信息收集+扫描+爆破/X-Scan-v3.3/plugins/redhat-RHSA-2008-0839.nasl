
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33893);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0839: postfix");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0839");
 script_set_attribute(attribute: "description", value: '
  Updated postfix packages that fix a security issue are now available for
  Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL),
  and TLS.

  A flaw was found in the way Postfix dereferences symbolic links. If a local
  user has write access to a mail spool directory with no root mailbox, it
  may be possible for them to append arbitrary data to files that root has
  write permission to. (CVE-2008-2936)

  Red Hat would like to thank Sebastian Krahmer for responsibly disclosing
  this issue.

  All users of postfix should upgrade to these updated packages, which
  contain a backported patch that resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0839.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2936");
script_summary(english: "Check for the version of the postfix packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"postfix-2.3.3-2.1.el5_2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postfix-pflogsumm-2.3.3-2.1.el5_2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postfix-2.0.16-14.1.RHEL3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postfix-2.2.10-1.2.1.el4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postfix-pflogsumm-2.2.10-1.2.1.el4_7", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
