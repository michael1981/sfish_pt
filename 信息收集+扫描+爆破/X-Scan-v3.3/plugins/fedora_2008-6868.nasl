
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6868
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33769);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-6868: phpMyAdmin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6868 (phpMyAdmin)");
 script_set_attribute(attribute: "description", value: "phpMyAdmin is a tool written in PHP intended to handle the administration of
MySQL over the Web. Currently it can create and drop databases,
create/drop/alter tables, delete/edit/add fields, execute any SQL statement,
manage keys on fields, manage privileges,export data into various formats and
is available in 50 languages

-
Update Information:

This update solves PMASA-2008-6 (phpMyAdmin security announcement) from
2008-07-28: Cross-site Framing; XSS in setup.php; see
[9]http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2008-6    -
[interface] Table list pagination in navi  - [profiling] Profiling causes query
to be executed again (really causes a problem in case of INSERT/UPDATE)  -
[import] SQL file import very slow on Windows  - [XHTML] problem with tabindex
and radio fields  - [interface] tabindex not set correctly  - [views] VIEW name
created via the GUI was not protected with backquotes  - [interface] Deleting
multiple views (space in name)  - [parser] SQL parser removes essential space
-
[export] CSV for MS Excel incorrect escaping of double quotes  - [interface]
Font size option problem when no config file  - [relation] Relationship view
should check for changes  - [history] Do not save too big queries in history  -
[security] Do not show version info on login screen  - [import] Potential data
loss on import resubmit  - [export] Safari and timedate  - [import, export]
Import/Export fails because of Mac files  - [security] protection against cross
-
frame scripting and new directive AllowThirdPartyFraming  - [security] possible
XSS during setup  - [interface] revert language changing problem introduced wit
h
2.11.7.1    phpMyAdmin 2.11.8.1 is a bugfix-only version containing normal bug
fixes and two security fixes. This version is identical to 2.11.8, except it
includes a fix for a notice about 'lang'.
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

if ( rpm_check( reference:"phpMyAdmin-2.11.8.1-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
