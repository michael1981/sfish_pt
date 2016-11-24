
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13946);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2002:042: LPRng");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:042 (LPRng).");
 script_set_attribute(attribute: "description", value: "Matthew Caron pointed out that using the LPRng default configuration,
the lpd daemon will accept job submissions from any remote host. These
updated LPRng packages modify the job submission policy in
/etc/lpd.perms to refuse print jobs from remote hosts by default.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:042");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0378");
script_summary(english: "Check for the version of the LPRng package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"LPRng-3.7.4-7.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"LPRng-3.8.6-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"LPRng-", release:"MDK8.1")
 || rpm_exists(rpm:"LPRng-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0378", value:TRUE);
}
exit(0, "Host is not affected");
