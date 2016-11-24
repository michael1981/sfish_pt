
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14014);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:030-1: file");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:030-1 (file).");
 script_set_attribute(attribute: "description", value: "A memory allocation problem in file was found by Jeff Johnson, and a
stack overflow corruption problem was found by David Endler. These
problems have been corrected in file version 3.41 and likely affect
all previous version. These problems pose a security threat as they
can be used to execute arbitrary code by an attacker under the
privileges of another user. Note that the attacker must first
somehow convince the target user to execute file against a specially
crafted file that triggers the buffer overflow in file.
Update:
The 8.2 and 9.0 packages installed data in a different directory than
where they should have been installed, which broke compatability with
a small number of programs. These updated packages place those files
back in the appropriate location.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:030-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0102");
script_summary(english: "Check for the version of the file package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"file-3.41-1.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"file-3.41-1.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"file-", release:"MDK8.2")
 || rpm_exists(rpm:"file-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0102", value:TRUE);
}
exit(0, "Host is not affected");
