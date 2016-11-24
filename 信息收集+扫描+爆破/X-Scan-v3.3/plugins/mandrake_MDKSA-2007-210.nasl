
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27817);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDKSA-2007:210: xfs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:210 (xfs).");
 script_set_attribute(attribute: "description", value: "Integer overflow in the build_range function in X.Org X Font Server
(xfs) before 1.0.5 allows context-dependent attackers to execute
arbitrary code via (1) QueryXBitmaps and (2) QueryXExtents protocol
requests with crafted size values, which triggers a heap-based buffer
overflow. (CVE-2007-4568)
The swap_char2b function in X.Org X Font Server (xfs) before 1.0.5
allows context-dependent attackers to execute arbitrary code via (1)
QueryXBitmaps and (2) QueryXExtents protocol requests with crafted
size values that specify an arbitrary number of bytes to be swapped
on the heap, which triggers heap corruption. (CVE-2007-4990)
Updated package fixes these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:210");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-4568", "CVE-2007-4990");
script_summary(english: "Check for the version of the xfs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xfs-1.0.2-13.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xfs-1.0.4-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xfs-", release:"MDK2007.0")
 || rpm_exists(rpm:"xfs-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-4568", value:TRUE);
 set_kb_item(name:"CVE-2007-4990", value:TRUE);
}
exit(0, "Host is not affected");
