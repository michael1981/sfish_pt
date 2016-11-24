
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9336
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34684);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-9336: phpMyAdmin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9336 (phpMyAdmin)");
 script_set_attribute(attribute: "description", value: "phpMyAdmin is a tool written in PHP intended to handle the administration of
MySQL over the Web. Currently it can create and drop databases,
create/drop/alter tables, delete/edit/add fields, execute any SQL statement,
manage keys on fields, manage privileges,export data into various formats and
is available in 50 languages

-
Update Information:

This update by upstream to phpMyAdmin 3.0.1.1 solves CVE-2008-4775, a XSS issue
in pmd_pdf.php via db parameter when register_globals is enabled.    - [GUI] SQ
L
error after sorting a subset  - [lang] Catalan update  - [lang] Russian update
- [import] Temporary uploaded file not deleted  - [auth] Cannot create database
after session timeout  - [core] ForceSSL generates incorrectly escaped
redirections (this time with the correct fix)  - [lang] Hungarian update  -
[core] Properly truncate SQL to avoid half of html tags  - [lang] Romanian
update  - [structure] Incorrect index choice shown when modifying an index   -
[interface] Misleading message after cancelling an action   - [lang] Croatian
update  - [lang] Finnish update  - [lang] Polish update  - [lang] Japanese
update  - [privileges] Wrong message when changing password  - [core] Cannot
disable PMA tables   - [lang] Problems with Italian language file  - [interface
]
ShowChgPassword setting not respected  - [security] XSS in a Designer component
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-0095", "CVE-2008-4775");
script_summary(english: "Check for the version of the phpMyAdmin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"phpMyAdmin-3.0.1.1-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
