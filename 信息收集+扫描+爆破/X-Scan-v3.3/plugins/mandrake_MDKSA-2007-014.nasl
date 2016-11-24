
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24630);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:014: bluez-utils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:014 (bluez-utils).");
 script_set_attribute(attribute: "description", value: "hidd in BlueZ (bluez-utils) before 2.25 allows remote attackers to
obtain control of the (1) Mouse and (2) Keyboard Human Interface Device
(HID) via a certain configuration of two HID (PSM) endpoints, operating
as a server, aka HidAttack.
hidd is not enabled by default on Mandriva 2006.0. This update adds the
--nocheck option (disabled by default) to the hidd binary, which
defaults to rejecting connections from unknown devices unless --nocheck
is enabled.
The updated packages have been patched to correct this problem
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:014");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-6899");
script_summary(english: "Check for the version of the bluez-utils package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"bluez-utils-2.19-7.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bluez-utils-cups-2.19-7.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"bluez-utils-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-6899", value:TRUE);
}
exit(0, "Host is not affected");
