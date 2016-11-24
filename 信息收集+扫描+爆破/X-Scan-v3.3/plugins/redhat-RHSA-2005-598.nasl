
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19409);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2005-598: sysreport");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-598");
 script_set_attribute(attribute: "description", value: '
  An updated sysreport package that fixes an insecure temporary file flaw is
  now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Sysreport is a utility that gathers information about a system\'s hardware
  and configuration. The information can then be used for diagnostic purposes
  and debugging.

  Bill Stearns discovered a bug in the way sysreport creates temporary files.
  It is possible that a local attacker could obtain sensitive information
  about the system when sysreport is run. The Common Vulnerabilities and
  Exposures project assigned the name CAN-2005-2104 to this issue.

  Users of sysreport should update to this erratum package, which contains a
  patch that resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-598.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2104");
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

if ( rpm_check( reference:"sysreport-1.3.7.0-7", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sysreport-1.3.7.2-9", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sysreport-1.3.15-5", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
