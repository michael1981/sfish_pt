
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11221
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35096);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-11221: phpMyAdmin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11221 (phpMyAdmin)");
 script_set_attribute(attribute: "description", value: "phpMyAdmin is a tool written in PHP intended to handle the administration of
MySQL over the Web. Currently it can create and drop databases,
create/drop/alter tables, delete/edit/add fields, execute any SQL statement,
manage keys on fields, manage privileges,export data into various formats and
is available in 50 languages

-
Update Information:

Improvements for 3.1.1.0:  - [core] Navi panel server links wrong  - [core] bad
session.save_path not detected  - [core] Re-login causes PMA to forget current
table name   - [export] do not include view name in export  - [display] enable
copying of auto increment by default  - [core] do not bail out creating session
on any PHP warning  - [display] properly update tooltips in navigation frame  -
[core] do not use ctype if it is not available  - [display] HeaderFlipType
'fake' problems  - [display] Incorrect size for view  - [display] Drop-down men
u
blinking in FF  - [lang] Catalan update  - [lang] Finnish update  - [core] Avoi
d
error with BLOBstreaming support requiring SUPER privilege  - [security]
possible XSRF on several pages
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-0095");
script_summary(english: "Check for the version of the phpMyAdmin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"phpMyAdmin-3.1.1-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
