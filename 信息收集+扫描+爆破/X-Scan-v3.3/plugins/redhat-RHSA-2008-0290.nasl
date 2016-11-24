
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32472);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0290: samba");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0290");
 script_set_attribute(attribute: "description", value: '
  Updated samba packages that fix a security issue and two bugs are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Samba is a suite of programs used by machines to share files, printers, and
  other information.

  A heap-based buffer overflow flaw was found in the way Samba clients handle
  over-sized packets. If a client connected to a malicious Samba server, it
  was possible to execute arbitrary code as the Samba client user. It was
  also possible for a remote user to send a specially crafted print request
  to a Samba server that could result in the server executing the vulnerable
  client code, resulting in arbitrary code execution with the permissions of
  the Samba server. (CVE-2008-1105)

  Red Hat would like to thank Alin Rad Pop of Secunia Research for
  responsibly disclosing this issue.

  This update also addresses two issues which prevented Samba from joining
  certain Windows domains with tightened security policies, and prevented
  certain signed SMB content from working as expected:

  * when some Windows   2000-based domain controllers were set to use
  mandatory signing, Samba clients would drop the connection because of an
  error when generating signatures. This presented as a "Server packet had
  invalid SMB signature" error to the Samba client. This update corrects the
  signature generation error.

  * Samba servers using the "net ads join" command to connect to a Windows
  Server   2003-based domain would fail with "failed to get schannel session
  key from server" and "NT_STATUS_ACCESS_DENIED" errors. This update
  correctly binds to the NETLOGON share, allowing Samba servers to connect to
  the domain properly.

  Users of Samba are advised to upgrade to these updated packages, which
  contain a backported patch to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0290.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1105");
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

if ( rpm_check( reference:"samba-3.0.28-1.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.28-1.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.28-1.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.28-1.el5_2.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
