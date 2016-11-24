
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6133
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34124);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-6133: bluez-utils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6133 (bluez-utils)");
 script_set_attribute(attribute: "description", value: "Bluetooth utilities (bluez-utils):
- hcitool
- hciattach
- hciconfig
- hcid
- l2ping
- start scripts (Red Hat)
- pcmcia configuration files

The BLUETOOTH trademarks are owned by Bluetooth SIG, Inc., U.S.A.

-
ChangeLog:


Update information :

* Thu Jul 10 2008 - Will Woods <wwoods redhat com> - 3.35-3
- Re-add hid2hci
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2374");
script_summary(english: "Check for the version of the bluez-utils package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"bluez-utils-3.35-3.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
