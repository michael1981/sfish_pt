
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28244);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1013: samba");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1013");
 script_set_attribute(attribute: "description", value: '
  Updated samba packages that fix several security issues are now available
  for Red Hat Enterprise Linux 2.1 and 3.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Samba is a suite of programs used by machines to share files, printers, and
  other information.

  A buffer overflow flaw was found in the way Samba creates NetBIOS replies.
  If a Samba server is configured to run as a WINS server, a remote
  unauthenticated user could cause the Samba server to crash or execute
  arbitrary code. (CVE-2007-5398)

  A heap-based buffer overflow flaw was found in the way Samba authenticates
  users. A remote unauthenticated user could trigger this flaw to cause the
  Samba server to crash. Careful analysis of this flaw has determined that
  arbitrary code execution is not possible, and under most circumstances will
  not result in a crash of the Samba server. (CVE-2007-4572)

  Red Hat would like to thank Alin Rad Pop of Secunia Research, and the Samba
  developers for responsibly disclosing these issues.

  Users of Samba are advised to ugprade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1013.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4572", "CVE-2007-5398");
script_summary(english: "Check for the version of the samba packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"samba-2.2.12-1.21as.8.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.12-1.21as.8.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.12-1.21as.8.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.12-1.21as.8.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.9-1.3E.14.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.9-1.3E.14.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.9-1.3E.14.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.9-1.3E.14.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
