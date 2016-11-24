
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39597);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1138: openswan");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1138");
 script_set_attribute(attribute: "description", value: '
  Updated openswan packages that fix multiple security issues are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Openswan is a free implementation of Internet Protocol Security (IPsec)
  and Internet Key Exchange (IKE). IPsec uses strong cryptography to provide
  both authentication and encryption services. These services allow you to
  build secure tunnels through untrusted networks. Everything passing through
  the untrusted network is encrypted by the IPsec gateway machine, and
  decrypted by the gateway at the other end of the tunnel. The resulting
  tunnel is a virtual private network (VPN).

  Multiple insufficient input validation flaws were found in the way
  Openswan\'s pluto IKE daemon processed some fields of X.509 certificates. A
  remote attacker could provide a specially-crafted X.509 certificate that
  would crash the pluto daemon. (CVE-2009-2185)

  All users of openswan are advised to upgrade to these updated packages,
  which contain a backported patch to correct these issues. After installing
  this update, the ipsec service will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1138.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2185");
script_summary(english: "Check for the version of the openswan packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openswan-2.6.14-1.el5_3.3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openswan-doc-2.6.14-1.el5_3.3", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openswan-2.6.14-1.el5_3.3", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openswan-doc-2.6.14-1.el5_3.3", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
