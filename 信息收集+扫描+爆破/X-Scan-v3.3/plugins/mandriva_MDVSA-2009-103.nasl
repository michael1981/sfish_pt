
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38658);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:103: udev");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:103 (udev).");
 script_set_attribute(attribute: "description", value: "Security vulnerabilities have been identified and fixed in udev.
udev before 1.4.1 does not verify whether a NETLINK message originates
from kernel space, which allows local users to gain privileges by
sending a NETLINK message from user space (CVE-2009-1185).
Buffer overflow in the util_path_encode function in
udev/lib/libudev-util.c in udev before 1.4.1 allows local users to
cause a denial of service (service outage) via vectors that trigger
a call with crafted arguments (CVE-2009-1186).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:103");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1185", "CVE-2009-1186");
script_summary(english: "Check for the version of the udev package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libvolume_id0-118-6.3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libvolume_id0-devel-118-6.3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"udev-118-6.3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"udev-doc-118-6.3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"udev-tools-118-6.3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libudev0-128-2.2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libudev0-devel-128-2.2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libvolume_id1-128-2.2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libvolume_id1-devel-128-2.2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"udev-128-2.2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"udev-doc-128-2.2mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"udev-", release:"MDK2008.1")
 || rpm_exists(rpm:"udev-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-1185", value:TRUE);
 set_kb_item(name:"CVE-2009-1186", value:TRUE);
}
exit(0, "Host is not affected");
