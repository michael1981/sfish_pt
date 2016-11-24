
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2419
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36291);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-2419: NetworkManager-pptp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2419 (NetworkManager-pptp)");
 script_set_attribute(attribute: "description", value: "This package contains software for integrating PPTP VPN support with
the NetworkManager and the GNOME desktop.

-
ChangeLog:


Update information :

* Thu Mar  5 2009 Dan Williams <dcbw redhat com> 1:0.7.0.99-1
- Update to 0.7.1rc3
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0365", "CVE-2009-0578");
script_summary(english: "Check for the version of the NetworkManager-pptp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"NetworkManager-pptp-0.7.0.99-1.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
