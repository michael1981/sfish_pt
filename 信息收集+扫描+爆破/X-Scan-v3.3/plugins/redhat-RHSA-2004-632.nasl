
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15741);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2004-632: samba");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-632");
 script_set_attribute(attribute: "description", value: '
  Updated samba packages that fix various security vulnerabilities are now
  available.

  Samba provides file and printer sharing services to SMB/CIFS clients.

  During a code audit, Stefan Esser discovered a buffer overflow in Samba
  versions prior to 3.0.8 when handling unicode filenames. An authenticated
  remote user could exploit this bug which may lead to arbitrary code
  execution on the server. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0882 to this issue. Red Hat
  believes that the Exec-Shield technology (enabled by default since Update
  3) will block attempts to remotely exploit this vulnerability on x86
  architectures.

  Additionally, a bug was found in the input validation routines in versions
  of Samba prior to 3.0.8 that caused the smbd process to consume abnormal
  amounts of system memory. An authenticated remote user could exploit this
  bug to cause a denial of service. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-0930 to this issue.

  Users of Samba should upgrade to these updated packages, which contain
  backported security patches, and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-632.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0882", "CVE-2004-0930");
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

if ( rpm_check( reference:"samba-2.2.12-1.21as.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.12-1.21as.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.12-1.21as.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.12-1.21as.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-3.0.7-1.3E.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.7-1.3E.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.7-1.3E.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.7-1.3E.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
