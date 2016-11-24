
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15428);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-498: samba");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-498");
 script_set_attribute(attribute: "description", value: '
  Updated samba packages that fix an input validation vulnerability are now
  available.

  Samba provides file and printer sharing services to SMB/CIFS clients.

  Karol Wiesek discovered an input validation issue in Samba prior to 3.0.6.
  An authenticated user could send a carefully crafted request to the Samba
  server, which would allow access to files outside of the configured file
  share. Note: Such files would have to be readable by the account used
  for the connection. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0815 to this issue.

  This issue does not affect Red Hat Enterprise Linux 3 as a previous erratum
  updated to Samba 3.0.6 which is not vulnerable to this issue.

  Users of Samba should upgrade to these updated packages, which contain an
  upgrade to Samba-2.2.12, which is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-498.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0815");
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

if ( rpm_check( reference:"samba-2.2.12-1.21as", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.12-1.21as", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.12-1.21as", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.12-1.21as", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
