
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36425);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:204: blender");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:204 (blender).");
 script_set_attribute(attribute: "description", value: "Stefan Cornelius of Secunia Research reported a boundary error when
Blender processed RGBE images which could be used to execute arbitrary
code with the privileges of the user running Blender if a specially
crafted .hdr or .blend file were opened(CVE-2008-1102).
As well, multiple vulnerabilities involving insecure usage of temporary
files had also been reported (CVE-2008-1103).
The updated packages have been patched to prevent these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:204");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1102", "CVE-2008-1103");
script_summary(english: "Check for the version of the blender package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"blender-2.45-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"blender-2.45-7.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"blender-", release:"MDK2008.0")
 || rpm_exists(rpm:"blender-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-1102", value:TRUE);
 set_kb_item(name:"CVE-2008-1103", value:TRUE);
}
exit(0, "Host is not affected");
