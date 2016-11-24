
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24575);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:190: mutt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:190 (mutt).");
 script_set_attribute(attribute: "description", value: "A race condition in the safe_open function in the Mutt mail client
1.5.12 and earlier, when creating temporary files in an NFS filesystem,
allows local users to overwrite arbitrary files due to limitations of
the use of the O_EXCL flag on NFS filesystems. (CVE-2006-5297)
The mutt_adv_mktemp function in the Mutt mail client 1.5.12 and earlier
does not properly verify that temporary files have been created with
restricted permissions, which might allow local users to create files
with weak permissions via a race condition between the mktemp and
safe_fopen function calls. (CVE-2006-5298)
Updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:190");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-5297", "CVE-2006-5298");
script_summary(english: "Check for the version of the mutt package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mutt-1.5.9i-9.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mutt-utf8-1.5.9i-9.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mutt-1.5.11-5.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mutt-utf8-1.5.11-5.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mutt-", release:"MDK2006.0")
 || rpm_exists(rpm:"mutt-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-5297", value:TRUE);
 set_kb_item(name:"CVE-2006-5298", value:TRUE);
}
exit(0, "Host is not affected");
