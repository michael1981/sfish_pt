
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-665
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25939);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-665: ipsec-tools");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-665 (ipsec-tools)");
 script_set_attribute(attribute: "description", value: "This is the IPsec-Tools package.  You need this package in order to
really use the IPsec functionality in the linux-2.5+ kernels.  This
package builds:

- setkey, a program to directly manipulate policies and SAs
- racoon, an IKEv1 keying daemon



Update information :

* Mon Apr 23 2007 Steve Grubb <sgrubb redhat com> - 0.6.5-8
- Upstream fix for Racoon DOS, informational delete must be encrypted
- Resolves: rhbz#235388 - CVE-2007-1841 ipsec-tools racoon DoS
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1841");
script_summary(english: "Check for the version of the ipsec-tools package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ipsec-tools-0.6.5-8.fc6", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
