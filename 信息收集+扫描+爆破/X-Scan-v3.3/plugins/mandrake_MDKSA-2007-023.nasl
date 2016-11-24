
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24638);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:023: libgtop2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:023 (libgtop2).");
 script_set_attribute(attribute: "description", value: "Stack-based buffer overflow in the glibtop_get_proc_map_s function in
libgtop before 2.14.6 (libgtop2) allows local users to cause a denial
of service (crash) and possibly execute arbitrary code via a process
with a long filename that is mapped in its address space, which
triggers the overflow in gnome-system-monitor.
The updated packages have been patched to correct this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:023");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-0235");
script_summary(english: "Check for the version of the libgtop2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libgtop2-2.14.3-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtop2.0_7-2.14.3-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgtop2.0_7-devel-2.14.3-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libgtop2-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2007-0235", value:TRUE);
}
exit(0, "Host is not affected");
