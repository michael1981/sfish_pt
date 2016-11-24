
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12320);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2002-173: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-173");
 script_set_attribute(attribute: "description", value: '
  Updated Kerberos 5 packages are now available for Red Hat LInux Advanced
  Server. These updates fix a buffer overflow in the XDR decoder.

  Sun RPC is a remote procedure call framework which allows clients to invoke
  procedures in a server process over a network. XDR is a mechanism for
  encoding data structures for use with RPC.

  The Kerberos 5 network authentication system contains an RPC library which
  includes an XDR decoder derived from Sun\'s RPC implementation. The Sun
  implementation was recently demonstrated to be vulnerable to a heap
  overflow. It is believed that the attacker needs to be able to
  authenticate to the kadmin daemon for this attack to be successful. No
  exploits are known to currently exist.

  All users should upgrade to these errata packages which contain an updated
  version of Kerberos 5 which is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-173.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-0391");
script_summary(english: "Check for the version of the krb packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"krb5-devel-1.2.2-14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
