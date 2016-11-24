
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23885);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:135: freeciv");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:135 (freeciv).");
 script_set_attribute(attribute: "description", value: "Buffer overflow in Freeciv 2.1.0-beta1 and earlier, and SVN 15 Jul
2006 and earlier, allows remote attackers to cause a denial of service
(crash) and possibly execute arbitrary code via a (1) negative
chunk_length or a (2) large chunk->offset value in a
PACKET_PLAYER_ATTRIBUTE_CHUNK packet in the
generic_handle_player_attribute_chunk function in common/packets.c, and
(3) a large packet->length value in the handle_unit_orders function in
server/unithand.c.
The updated packages have been patched to fix this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:135");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-3913");
script_summary(english: "Check for the version of the freeciv package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"freeciv-client-2.0.4-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeciv-data-2.0.4-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freeciv-server-2.0.4-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"freeciv-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-3913", value:TRUE);
}
exit(0, "Host is not affected");
