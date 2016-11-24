
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24553);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:167: gzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:167 (gzip).");
 script_set_attribute(attribute: "description", value: "NULL Dereference (CVE-2006-4334)
A stack modification vulnerability (where a stack buffer can be
modified out of bounds, but not in the traditional stack overrun sense)
exists in the LZH decompression support of gzip. (CVE-2006-4335)
A .bss buffer underflow exists in gzip's pack support, where a loop
from build_tree() does not enforce any lower bound while constructing
the prefix table. (CVE-2006-4336)
A .bss buffer overflow vulnerability exists in gzip's LZH support, due
to it's inability to handle exceptional input in the make_table()
function, a pathological decoding table can be constructed in such a
way as to generate counts so high that the rapid growth of `nextcode`
exceeds the size of the table[] buffer. (CVE-2006-4337)
A possible infinite loop exists in code from unlzh.c for traversing the
branches of a tree structure. This makes it possible to disrupt the
operation of automated systems relying on gzip for data decompression,
resulting in a minor DoS. (CVE-2006-4338) Updated packages have been
patched to address these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:167");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4334", "CVE-2006-4335", "CVE-2006-4336", "CVE-2006-4337", "CVE-2006-4338");
script_summary(english: "Check for the version of the gzip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gzip-1.2.4a-15.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gzip-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-4334", value:TRUE);
 set_kb_item(name:"CVE-2006-4335", value:TRUE);
 set_kb_item(name:"CVE-2006-4336", value:TRUE);
 set_kb_item(name:"CVE-2006-4337", value:TRUE);
 set_kb_item(name:"CVE-2006-4338", value:TRUE);
}
exit(0, "Host is not affected");
