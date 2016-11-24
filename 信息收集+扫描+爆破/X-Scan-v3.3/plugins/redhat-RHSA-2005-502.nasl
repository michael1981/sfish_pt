
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18474);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-502: sysreport");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-502");
 script_set_attribute(attribute: "description", value: '
  An updated sysreport package that fixes an information disclosure flaw is
  now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team

  Sysreport is a utility that gathers information about a system\'s hardware
  and configuration. The information can then be used for diagnostic purposes
  and debugging.

  When run by the root user, sysreport includes the contents of the
  /etc/sysconfig/rhn/up2date configuration file. If up2date has been
  configured to connect to a proxy server that requires an authentication
  password, that password is included in plain text in the system report.
  The Common Vulnerabilities and Exposures project assigned the name
  CAN-2005-1760 to this issue.

  Users of sysreport should update to this erratum package, which contains a
  patch that removes any proxy authentication passwords.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-502.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1760");
script_summary(english: "Check for the version of the sysreport packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sysreport-1.3.7.0-4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sysreport-1.3.7.2-6", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sysreport-1.3.15-2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
