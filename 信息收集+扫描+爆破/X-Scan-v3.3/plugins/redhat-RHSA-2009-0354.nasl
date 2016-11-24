
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35945);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0354: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0354");
 script_set_attribute(attribute: "description", value: '
  Updated evolution-data-server and evolution28-evolution-data-server
  packages that fix multiple security issues are now available for Red Hat
  Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Evolution Data Server provides a unified back-end for applications which
  interact with contacts, task, and calendar information. Evolution Data
  Server was originally developed as a back-end for Evolution, but is now
  used by multiple other applications.

  Evolution Data Server did not properly check the Secure/Multipurpose
  Internet Mail Extensions (S/MIME) signatures used for public key encryption
  and signing of e-mail messages. An attacker could use this flaw to spoof a
  signature by modifying the text of the e-mail message displayed to the
  user. (CVE-2009-0547)

  It was discovered that Evolution Data Server did not properly validate NTLM
  (NT LAN Manager) authentication challenge packets. A malicious server using
  NTLM authentication could cause an application using Evolution Data Server
  to disclose portions of its memory or crash during user authentication.
  (CVE-2009-0582)

  Multiple integer overflow flaws which could cause heap-based buffer
  overflows were found in the Base64 encoding routines used by Evolution Data
  Server. This could cause an application using Evolution Data Server to
  crash, or, possibly, execute an arbitrary code when large untrusted data
  blocks were Base64-encoded. (CVE-2009-0587)

  All users of evolution-data-server and evolution28-evolution-data-server
  are advised to upgrade to these updated packages, which contain backported
  patches to correct these issues. All running instances of Evolution Data
  Server and applications using it (such as Evolution) must be restarted for
  the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0354.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
script_summary(english: "Check for the version of the evolution packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"evolution-data-server-1.12.3-10.el5_3.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-data-server-devel-1.12.3-10.el5_3.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-data-server-doc-1.12.3-10.el5_3.3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution28-evolution-data-server-1.8.0-37.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution28-evolution-data-server-devel-1.8.0-37.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
