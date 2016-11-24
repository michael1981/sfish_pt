
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27602);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1020: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1020");
 script_set_attribute(attribute: "description", value: '
  Updated CUPS packages that fix a security issue in the Internet Printing
  Protocol (IPP) handling and correct some bugs are now available for Red Hat
  Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX(R) operating systems.

  A flaw was found in the way CUPS handles certain Internet Printing Protocol
  (IPP) tags. A remote attacker who is able to connect to the IPP TCP port
  could send a malicious request causing the CUPS daemon to crash, or
  potentially execute arbitrary code. Please note that the default CUPS
  configuration does not allow remote hosts to connect to the IPP TCP port.
  (CVE-2007-4351)

  Red Hat would like to thank Alin Rad Pop for reporting this issue.

  All CUPS users are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue.

  In addition, the following bugs were fixed:

  * the CUPS service has been changed to start after sshd, to avoid causing
  delays when logging in when the system is booted.

  * the logrotate settings have been adjusted so they do not cause CUPS to
  reload its configuration. This is to avoid re-printing the current job,
  which could occur when it was a long-running job.

  * a bug has been fixed in the handling of the If-Modified-Since: HTTP
  header.

  * in the LSPP configuration, labels for labeled jobs did not line-wrap.
  This has been fixed.

  * an access check in the LSPP configuration has been made more secure.

  * the cups-lpd service no longer ignores the "-odocument-format=..."
  option.

  * a memory allocation bug has been fixed in cupsd.

  * support for UNIX domain sockets authentication without passwords has been
  added.

  * in the LSPP configuration, a problem that could lead to cupsd crashing
  has been fixed.

  * the error handling in the initscript has been improved.

  * The job-originating-host-name attribute was not correctly set for jobs
  submitted via the cups-lpd service. This has been fixed.

  * a problem with parsing IPv6 addresses in the configuration file has been
  fixed.

  * a problem that could lead to cupsd crashing when it failed to open a
  "file:" URI has been fixed.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1020.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4351");
script_summary(english: "Check for the version of the cups packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.2.4-11.14.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.2.4-11.14.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.2.4-11.14.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-lpd-1.2.4-11.14.el5_1.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
