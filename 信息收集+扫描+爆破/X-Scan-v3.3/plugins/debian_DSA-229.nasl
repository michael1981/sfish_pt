# This script was automatically generated from the dsa-229
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15066);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "229");
 script_cve_id("CVE-2003-0025");
 script_bugtraq_id(6559);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-229 security update');
 script_set_attribute(attribute: 'description', value:
'Jouko Pynnonen discovered a problem with IMP, a web based IMAP mail
program.  Using carefully crafted URLs a remote attacker is able to
inject SQL code into SQL queries without proper user authentication.
Even though results of SQL queries aren\'t directly readable from the
screen, an attacker might update their mail signature to contain wanted
query results and then view it on the preferences page of IMP.
The impact of SQL injection depends heavily on the underlying database
and its configuration.  If PostgreSQL is used, it\'s possible to
execute multiple complete SQL queries separated by semicolons.  The
database contains session id\'s so the attacker might hijack sessions
of people currently logged in and read their mail.  In the worst case,
if the hordemgr user has the required privilege to use the COPY SQL
command (found in PostgreSQL at least), a remote user may read or
write to any file the database user (postgres) can.  The attacker may
then be able to run arbitrary shell commands by writing them to the
postgres user\'s ~/.psqlrc; they\'d be run when the user starts the psql
command which under some configurations happens regularly from a cron
script.
For the current stable distribution (woody) this problem has been
fixed in version 2.2.6-5.1.
For the old stable distribution (potato) this problem has been
fixed in version 2.2.6-0.potato.5.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-229');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your IMP packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA229] DSA-229-1 imp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-229-1 imp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'imp', release: '2.2', reference: '2.2.6-0.potato.5.1');
deb_check(prefix: 'imp', release: '3.0', reference: '2.2.6-5.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
