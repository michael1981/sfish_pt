
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1951
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31175);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-1951: sword");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1951 (sword)");
 script_set_attribute(attribute: "description", value: "The SWORD Project is the CrossWire Bible Society's free Bible software
project. Its purpose is to create cross-platform open-source tools--
covered by the GNU General Public License-- that allow programmers and
Bible societies to write new Bible software more quickly and easily. We
also create Bible study software for all readers, students, scholars,
and translators of the Bible, and have a growing collection of over 200
texts in over 50 languages.

-
ChangeLog:


Update information :

* Thu Feb 21 2008 Deji Akingunola <dakingun gmail com> - 1.5.10-2
- Fix command injection bug (Bug #433723)
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the sword package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"sword-1.5.10-2.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
