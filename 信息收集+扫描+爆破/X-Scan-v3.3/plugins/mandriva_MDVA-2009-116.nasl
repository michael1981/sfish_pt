
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39460);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2009:116: glibc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2009:116 (glibc).");
 script_set_attribute(attribute: "description", value: "New glibc release to fix some issues found in glibc 2.8 present in
Mandriva 2009.0:
- ulimit(UL_SETFSIZE) does not return the integer
part of the new file size limit divided by 512
(http://linuxtesting.org/results/report?num=S0167, Mandriva bug #51685)
- When including pthread.h and using pthread_cleanup_pop
or pthread_cleanup_pop_restore_np macros, a compiler
warning is issued or build error happens if -Werror is used
(http://sourceware.org/bugzilla/show_bug.cgi?id=7056, Mandriva
bug #49142)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2009:116");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the glibc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"glibc-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-doc-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-doc-pdf-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-i18ndata-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-static-devel-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"glibc-utils-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nscd-2.8-1.20080520.5.4mnb2", release:"MDK2009.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
