
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23901);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:157-1: musicbrainz");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:157-1 (musicbrainz).");
 script_set_attribute(attribute: "description", value: "Multiple buffer overflows in libmusicbrainz (aka mb_client or
MusicBrainz Client Library) 2.1.2 and earlier, and SVN 8406 and
earlier, allow remote attackers to cause a denial of service (crash) or
execute arbitrary code via (1) a long Location header by the HTTP
server, which triggers an overflow in the MBHttp::Download function in
lib/http.cpp; and (2) a long URL in RDF data, as demonstrated by a URL
in an rdf:resource field in an RDF XML document, which triggers
overflows in many functions in lib/rdfparse.c.
The updated packages have been patched to correct this issue.
Update:
Packages are now available for Mandriva Linux 2007.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:157-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4197");
script_summary(english: "Check for the version of the musicbrainz package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libmusicbrainz4-2.1.3-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmusicbrainz4-devel-2.1.3-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-musicbrainz-2.1.3-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"musicbrainz-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-4197", value:TRUE);
}
exit(0, "Host is not affected");
