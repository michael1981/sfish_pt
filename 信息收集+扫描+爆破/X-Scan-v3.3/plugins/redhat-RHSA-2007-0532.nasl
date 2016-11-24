
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25608);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0532: apache");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0532");
 script_set_attribute(attribute: "description", value: '
  Updated Apache httpd packages that correct two security issues are now
  available for Red Hat Enterprise Linux 2.1.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular Web server.

  The Apache HTTP Server did not verify that a process was an Apache child
  process before sending it signals. A local attacker who has the ability to
  run scripts on the Apache HTTP Server could manipulate the scoreboard and
  cause arbitrary processes to be terminated, which could lead to a denial of
  service. (CVE-2007-3304)

  A flaw was found in the Apache HTTP Server mod_status module. Sites with
  the server-status page publicly accessible and ExtendedStatus enabled were
  vulnerable to a cross-site scripting attack. On Red Hat Enterprise Linux
  the server-status page is not enabled by default and it is best practice to
  not make this publicly available. (CVE-2006-5752)

  Users of Apache should upgrade to these updated packages, which contain
  backported patches to correct these issues. Users should restart Apache
  after installing this update.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0532.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-5752", "CVE-2007-3304");
script_summary(english: "Check for the version of the apache packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apache-1.3.27-12.ent", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.27-12.ent", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.27-12.ent", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
