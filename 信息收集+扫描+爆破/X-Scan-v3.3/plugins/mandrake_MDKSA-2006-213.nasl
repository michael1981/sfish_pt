
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24598);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:213: chromium");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:213 (chromium).");
 script_set_attribute(attribute: "description", value: "Chromium is an OpenGL-based shoot them up game with fine graphics. It
is built with a private copy of libpng, and as such could be
susceptible to some of the same vulnerabilities:
Buffer overflow in the png_decompress_chunk function in pngrutil.c in
libpng before 1.2.12 allows context-dependent attackers to cause a
denial of service and possibly execute arbitrary code via unspecified
vectors related to 'chunk error processing,' possibly involving the
'chunk_name'. (CVE-2006-3334)
It is questionable whether this issue is actually exploitable, but the
patch to correct the issue has been included in versions < 1.2.12.
In addition, an patch to address several old vulnerabilities has been
applied to this build. (CVE-2002-1363, CVE-2004-0421, CVE-2004-0597,
CVE-2004-0598, CVE-2004-0599)
Packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:213");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1363", "CVE-2004-0421", "CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599", "CVE-2006-3334");
script_summary(english: "Check for the version of the chromium package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"chromium-0.9.12-25.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"chromium-setup-0.9.12-25.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"chromium-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2002-1363", value:TRUE);
 set_kb_item(name:"CVE-2004-0421", value:TRUE);
 set_kb_item(name:"CVE-2004-0597", value:TRUE);
 set_kb_item(name:"CVE-2004-0598", value:TRUE);
 set_kb_item(name:"CVE-2004-0599", value:TRUE);
 set_kb_item(name:"CVE-2006-3334", value:TRUE);
}
exit(0, "Host is not affected");
