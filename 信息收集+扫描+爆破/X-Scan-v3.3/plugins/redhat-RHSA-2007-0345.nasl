
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25267);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2007-0345: vixie");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0345");
 script_set_attribute(attribute: "description", value: '
  Updated vixie-cron packages that fix a denial of service issue are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The vixie-cron package contains the Vixie version of cron. Cron is a
  standard UNIX daemon that runs specified programs at scheduled times.

  Raphael Marichez discovered a denial of service bug in the way vixie-cron
  verifies crontab file integrity. A local user with the ability to create a
  hardlink to /etc/crontab can prevent vixie-cron from executing certain
  system cron jobs. (CVE-2007-1856)

  All users of vixie-cron should upgrade to these updated packages, which
  contain a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0345.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1856");
script_summary(english: "Check for the version of the vixie packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"vixie-cron-4.1-70.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vixie-cron-4.1-19.EL3", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"vixie-cron-4.1-47.EL4", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
