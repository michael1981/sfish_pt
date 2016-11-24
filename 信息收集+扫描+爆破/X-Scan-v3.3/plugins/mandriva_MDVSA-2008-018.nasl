
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38128);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:018: gftp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:018 (gftp).");
 script_set_attribute(attribute: "description", value: "Kalle Olavi Niemitalo found two boundary errors in the fsplib library,
a copy of which is included in gFTP source. A remote attacer could
trigger these vulnerabilities by enticing a user to download a file
with a specially crafted directory or file name, possibly resulting in
the execution of arbitrary code (CVE-2007-3962) or a denial of service
(CVE-2007-3961).
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:018");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-3961", "CVE-2007-3962");
script_summary(english: "Check for the version of the gftp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gftp-2.0.18-9.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gftp-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-3961", value:TRUE);
 set_kb_item(name:"CVE-2007-3962", value:TRUE);
}
exit(0, "Host is not affected");
