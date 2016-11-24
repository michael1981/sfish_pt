
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-7423
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39772);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-7423: openswan");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-7423 (openswan)");
 script_set_attribute(attribute: "description", value: "Openswan is a free implementation of IPsec & IKE for Linux.  IPsec is
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Openswan. It optionally also builds the Openswan KLIPS IPsec stack that
is an alternative for the NETKEY/XFRM IPsec stack that exists in the
default Linux kernel.

Openswan 2.6.x also supports IKEv2 (RFC4309)

-
ChangeLog:


Update information :

* Mon Jul  6 2009 Avesh Agarwal <avagarwa redhat com> - 2.6.21-2
- Openswan ASN.1 parser vulnerability (CVE-2009-2185)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0790", "CVE-2009-2185");
script_summary(english: "Check for the version of the openswan package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"openswan-2.6.21-2.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
