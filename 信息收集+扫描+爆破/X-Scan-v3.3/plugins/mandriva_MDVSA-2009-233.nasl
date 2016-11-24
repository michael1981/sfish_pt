
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40980);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:233: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:233 (kernel).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered and corrected in the Linux 2.6 kernel:
The Linux kernel 2.6.0 through 2.6.30.4, and 2.4.4 through 2.4.37.4,
does not initialize all function pointers for socket operations
in proto_ops structures, which allows local users to trigger a NULL
pointer dereference and gain privileges by using mmap to map page zero,
placing arbitrary code on this page, and then invoking an unavailable
operation, as demonstrated by the sendpage operation on a PF_PPPOX
socket. (CVE-2009-2692)
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:233");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-2692");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kernel-2.6.24.7-3mnb-1-1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-2.6.24.7-3mnb-1-1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-2.6.24.7-3mnb-1-1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-devel-2.6.24.7-3mnb-1-1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-devel-latest-2.6.24.7-3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-latest-2.6.24.7-3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-devel-2.6.24.7-3mnb-1-1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-devel-latest-2.6.24.7-3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-latest-2.6.24.7-3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.24.7-3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-laptop-2.6.24.7-3mnb-1-1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-laptop-devel-2.6.24.7-3mnb-1-1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-laptop-devel-latest-2.6.24.7-3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-laptop-latest-2.6.24.7-3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-2.6.24.7-3mnb-1-1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-devel-2.6.24.7-3mnb-1-1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-devel-latest-2.6.24.7-3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-latest-2.6.24.7-3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.24.7-3mnb-1-1mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-latest-2.6.24.7-3mnb1", release:"MDK2008.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2009-2692", value:TRUE);
}
exit(0, "Host is not affected");
