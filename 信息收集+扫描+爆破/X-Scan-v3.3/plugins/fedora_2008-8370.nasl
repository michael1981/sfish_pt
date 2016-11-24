
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8370
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34287);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-8370: phpMyAdmin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8370 (phpMyAdmin)");
 script_set_attribute(attribute: "description", value: "phpMyAdmin is a tool written in PHP intended to handle the administration of
MySQL over the Web. Currently it can create and drop databases,
create/drop/alter tables, delete/edit/add fields, execute any SQL statement,
manage keys on fields, manage privileges,export data into various formats and
is available in 50 languages

-
Update Information:

This update by upstream to phpMyAdmin 2.11.9.1 solves a not yet clearly
specified code execution vulnerability.    - [auth] Links to version number on
login screen   - [core] PMA does not start if ini_set() is disabled   -
[bookmarks] Saved queries greater than 1000 chars not displayed  - [export]
Export type 'replace' does not work   - [export] DROP PROCEDURE needs IF EXISTS
- [export] Numbers in Excel export  - [lang] Norwegian UTF-8 original file
remerged  - [parser] Undefined variable seen_from  - [security] Code execution
vulnerability
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the phpMyAdmin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"phpMyAdmin-2.11.9.1-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
