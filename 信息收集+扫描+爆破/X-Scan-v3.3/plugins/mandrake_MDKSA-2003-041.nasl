
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14025);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2003:041-1: mutt");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:041-1 (mutt).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in the mutt text-mode email client in
the IMAP code. This vulnerability can be exploited by a malicious
IMAP server to crash mutt or even execute arbitrary code with the
privilege of the user running mutt.
Update:
The packages for Mandrake Linux 9.1 and 9.1/PPC were not GPG-signed.
This has been fixed and as a result the md5sums have changed. Thanks
to Mark Lyda for pointing this out.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:041-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0140");
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

if ( rpm_check( reference:"mutt-1.4.1i-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mutt-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0140", value:TRUE);
}
exit(0, "Host is not affected");
