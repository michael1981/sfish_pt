
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18094);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-364: logwatch");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-364");
 script_set_attribute(attribute: "description", value: '
  An updated logwatch package that fixes a denial of service issue is now
  available.

  This update has been rated as having moderate security impact by the
  Red Hat Security Response Team.

  LogWatch is a customizable log analysis system. LogWatch parses
  through your system\'s logs for a given period of time and creates a
  report analyzing areas that you specify, in as much detail as you
  require.

  A bug was found in the logwatch secure script. If an attacker is able to
  inject an arbitrary string into the /var/log/secure file, it is possible to
  prevent logwatch from detecting malicious activity. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-1061 to this issue.

  All users of logwatch are advised to upgrade to this updated
  package, which contain backported fixes for this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-364.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1061");
script_summary(english: "Check for the version of the logwatch packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"logwatch-2.6-2.EL2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
