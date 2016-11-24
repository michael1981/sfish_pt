
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(28352);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDKSA-2007:233: cpio");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:233 (cpio).");
 script_set_attribute(attribute: "description", value: "Buffer overflow in the safer_name_suffix function in GNU cpio
has unspecified attack vectors and impact, resulting in a crashing
stack. This problem is originally found in tar, but affects cpio too,
due to similar code fragments. (CVE-2007-4476)
Directory traversal vulnerability in cpio 2.6 and earlier allows remote
attackers to write to arbitrary directories via a .. (dot dot) in a
cpio file. This is an old issue, affecting only Mandriva Corporate
Server 4 and Mandriva Linux 2007. (CVE-2005-1229)
Updated package fixes these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:233");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-1229", "CVE-2007-4476");
script_summary(english: "Check for the version of the cpio package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cpio-2.6-7.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cpio-2.7-3.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cpio-2.9-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cpio-", release:"MDK2007.0")
 || rpm_exists(rpm:"cpio-", release:"MDK2007.1")
 || rpm_exists(rpm:"cpio-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2005-1229", value:TRUE);
 set_kb_item(name:"CVE-2007-4476", value:TRUE);
}
exit(0, "Host is not affected");
