
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24599);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:214-1: gv");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:214-1 (gv).");
 script_set_attribute(attribute: "description", value: "Stack-based buffer overflow in the ps_gettext function in ps.c for GNU
gv 3.6.2, and possibly earlier versions, allows user-assisted attackers
to execute arbitrary code via a PostScript (PS) file with certain
headers that contain long comments, as demonstrated using the
DocumentMedia header.
Packages have been patched to correct this issue.
Update:
The patch used in the previous update still left the possibility of
causing X to consume unusual amounts of memory if gv is used to view a
carefully crafted image designed to exploit CVE-2006-5864. This update
uses an improved patch to address this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:214-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-5864");
script_summary(english: "Check for the version of the gv package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gv-3.6.1-4.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gv-3.6.1-7.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gv-", release:"MDK2006.0")
 || rpm_exists(rpm:"gv-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-5864", value:TRUE);
}
exit(0, "Host is not affected");
