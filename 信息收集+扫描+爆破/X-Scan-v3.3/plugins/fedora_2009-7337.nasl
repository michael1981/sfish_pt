
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-7337
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39605);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 9 2009-7337: phpMyAdmin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-7337 (phpMyAdmin)");
 script_set_attribute(attribute: "description", value: "phpMyAdmin is a tool written in PHP intended to handle the administration of
MySQL over the Web. Currently it can create and drop databases,
create/drop/alter tables, delete/edit/add fields, execute any SQL statement,
manage keys on fields, manage privileges,export data into various formats and
is available in 50 languages

-
Update Information:

The first security release for phpMyAdmin 3.2.0:  - [security] XSS: Insufficien
t
output sanitizing in bookmarks    This version contains a number of small new
features and some bug fixes:  - [core] better support for vendor customisation
(based on what Debian needs)  - [rfe] warn when session.gc_maxlifetime is less
than cookie validity  - [rfe] configurable default charset for import  - [rfe]
link to InnoDB status when error 150 occurs  - [rfe] strip ` from column names
on import  - [rfe] LeftFrameDBSeparator can be an array  - [privileges] Extra
back reference when editing table-specific privileges  - [display] Sortable
database columns  - [lang] Wrong string in setup script hints  - [cleanup] XHTM
L
cleanup,  - [display] Possibility of disabling the sliders  - [privileges]
Create user for existing database  - [privileges] Cleanup  - [auth]
AllowNoPasswordRoot error message is too vague   - [XHTML] View table
headers/footers completely  - [core] support column name having square brackets
- [lang] Lithuanian update  - [auth] New setting AllowNoPassword (supercedes
AllowNoPasswordRoot) that applies to all accounts (even the anonymous user)  -
[relation] Missing code with hashing for relationship editing  - [rfe] Added
option to disable mcrypt warning.  - [bug] Request-URI Too Large error from
Location header  - [rfe] Check for relations support on main page.  - [rfe]
Explanation for using Host table.  - [rfe] Link to download more themes.  -
[rfe] Add option to generate password on change password page.  - [rfe] Allow
logging of user status with Apache.  - [patch] None default is different than
other None in some languages.  - [lang] Chinese Simplified update  - [display]
Sort arrows problem  - [security] warn about existence of config directory on
main page  - [lang] Polish update  - [export] Escape new line in CSV export  -
[patch] Optimizations for PHP loops  - [import] SQL_MODE not saved during
Partial Import   - [auth] cache control missing (PHP-CGI)  - [parser] Incorrect
parsing of constraints in ALTER TABLE  - [status] Server status - replication
-
[edit] Multi-row change with ']' improved  - [rfe] Automatically copy generated
password  - [interface] Table with name 'log_views' is incorrectly displayed as
a view  - [patch] Detect mcrypt initialization failure  - [lang] Galician updat
e
- [lang] Swedish update  - [lang] Norwegian update  - [lang] Catalan update  -
[lang] Finnish update  - [lang] Hungarian update
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

if ( rpm_check( reference:"phpMyAdmin-3.2.0.1-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
