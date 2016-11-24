
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-5640
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33259);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-5640: phpMyAdmin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-5640 (phpMyAdmin)");
 script_set_attribute(attribute: "description", value: "phpMyAdmin is a tool written in PHP intended to handle the administration of
MySQL over the Web. Currently it can create and drop databases,
create/drop/alter tables, delete/edit/add fields, execute any SQL statement,
manage keys on fields, manage privileges,export data into various formats and
is available in 50 languages

-
Update Information:

This update solves PMASA-2008-4 (phpMyAdmin security announcement) from
2008-06-23: XSS on plausible insecure PHP installation; see
[9]http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2008-4    -
[interface] New field cannot be auto-increment and primary key   - [dbi]
Incorrect interpretation for some mysqli field flags   - [display] part 1: do
not display a TEXT utf8_bin as BLOB (fixed for mysqli extension only)  -
[interface] sanitize the after_field parameter, thanks to Norman Hippert  -
[structure] do not remove the BINARY attribute in drop-down   - [session]
Overriding session.hash_bits_per_character   - [interface] sanitize the table
comments in table print view, thanks to Norman Hippert  - [general]
Auto_Increment selected for TimeStamp by Default  - [display] No tilde for
InnoDB row counter when we know it for sure, thanks to Vladyslav Bakayev -
dandy76   - [display] alt text causes duplicated strings  - [interface] Cannot
upload BLOB into existing row   - [export] HTML in exports getting corrupted,
thanks to Jason Judge - jasonjudge  - [interface] BINARY not treated as BLOB:
update/delete issues   - [general] protection against XSS when register_globals
is on and .htaccess has no effect, thanks to Tim Starling  - [export] Firefox 3
and .sql.gz (corrupted); detect Gecko 1.9, thanks to Juergen Wind
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

if ( rpm_check( reference:"phpMyAdmin-2.11.7-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
