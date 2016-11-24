
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15598);
 script_version ("$Revision: 1.4 $");
 script_name(english: "MDKSA-2004:118: perl-Archive-Zip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:118 (perl-Archive-Zip).");
 script_set_attribute(attribute: "description", value: "Recently, it was noticed that several antivirus programs miss viruses that
are contained in ZIP archives with manipulated directory data. The global
archive directory of these ZIP file have been manipulated to indicate zero
file sizes.
Archive::Zip produces files of zero length when decompressing this type of
ZIP file. This causes AV products that use Archive::ZIP to fail to detect
viruses in manipulated ZIP archives. One of these products is amavisd-new.
The updated packages are patched to fix this problem.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:118");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the perl-Archive-Zip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-Archive-Zip-1.14-1.0.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
