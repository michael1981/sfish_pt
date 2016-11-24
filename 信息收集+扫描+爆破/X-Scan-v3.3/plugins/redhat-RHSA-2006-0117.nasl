
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21088);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0117: vixie");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0117");
 script_set_attribute(attribute: "description", value: '
  An updated vixie-cron package that fixes a bug and security issue is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The vixie-cron package contains the Vixie version of cron. Cron is a
  standard UNIX daemon that runs specified programs at scheduled times.

  A bug was found in the way vixie-cron installs new crontab files. It is
  possible for a local attacker to execute the crontab command in such a way
  that they can view the contents of another user\'s crontab file. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2005-1038 to
  this issue.

  This update also fixes an issue where cron jobs could start before their
  scheduled time.

  All users of vixie-cron should upgrade to this updated package, which
  contains backported patches and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0117.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1038");
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

if ( rpm_check( reference:"vixie-cron-4.1-10.EL3", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
