
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36065);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0402: openswan");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0402");
 script_set_attribute(attribute: "description", value: '
  Updated openswan packages that fix various security issues are now
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

  Gerd v. Egidy discovered a flaw in the Dead Peer Detection (DPD) in
  Openswan\'s pluto IKE daemon. A remote attacker could use a malicious DPD
  packet to crash the pluto daemon. (CVE-2009-0790)

  It was discovered that Openswan\'s livetest script created temporary files
  in an insecure manner. A local attacker could use this flaw to overwrite
  arbitrary files owned by the user running the script. (CVE-2008-4190)

  Note: The livetest script is an incomplete feature and was not
  automatically executed by any other script distributed with Openswan, or
  intended to be used at all, as was documented in its man page. In these
  updated packages, the script only prints an informative message and exits
  immediately when run.

  All users of openswan are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. After installing
  this update, the ipsec service will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0402.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-4190", "CVE-2009-0790");
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

if ( rpm_check( reference:"openswan-2.6.14-1.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openswan-doc-2.6.14-1.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
