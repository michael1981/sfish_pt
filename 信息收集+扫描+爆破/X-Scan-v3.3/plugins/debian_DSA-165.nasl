# This script was automatically generated from the dsa-165
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15002);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "165");
 script_cve_id("CVE-2002-0972", "CVE-2002-1398", "CVE-2002-1400", "CVE-2002-1401", "CVE-2002-1402");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-165 security update');
 script_set_attribute(attribute: 'description', value:
'Mordred Labs and others found several vulnerabilities in PostgreSQL,
an object-relational SQL database.  They are inherited from several
buffer overflows and integer overflows.  Specially crafted long date
and time input, currency, repeat data and long timezone names could
cause the PostgreSQL server to crash as well as specially crafted
input data for lpad() and rpad().  More buffer/integer overflows were
found in circle_poly(), path_encode() and path_addr().
Except for the last three, these problems are fixed in the upstream
release 7.2.2 of PostgreSQL which is the recommended version to use.
Most of these problems do not exist in the version of PostgreSQL that
Debian ships in the potato release since the corresponding
functionality is not yet implemented.  However, PostgreSQL 6.5.3 is
quite old and may bear more risks than we are aware of, which may
include further buffer overflows, and certainly include bugs that
threaten the integrity of your data.
You are strongly advised not to use this release but to upgrade your
system to Debian 3.0 (stable) including PostgreSQL release 7.2.1
instead, where many bugs have been fixed and new features introduced
to increase compatibility with the SQL standards.
If you consider an upgrade, please make sure to dump the entire
database system using the pg_dumpall utility.  Please take into
consideration that the newer PostgreSQL is more strict in its input
handling.  This means that tests like "foo = NULL" which are not valid
won\'t be accepted anymore.  It also means that when using UNICODE
encoding, ISO 8859-1 and ISO 8859-15 are no longer valid encodings to
use when inserting data into the relation.  In such a case you are
advised to convert the dump in question using
recode latin1..utf-16.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-165');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your PostgreSQL packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA165] DSA-165-1 postgresql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-165-1 postgresql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ecpg', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'libpgperl', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'libpgsql2', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'libpgtcl', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'odbc-postgresql', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'pgaccess', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'postgresql', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'postgresql-client', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'postgresql-contrib', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'postgresql-dev', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'postgresql-doc', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'postgresql-pl', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'postgresql-test', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'python-pygresql', release: '2.2', reference: '6.5.3-27.2');
deb_check(prefix: 'courier-authpostgresql', release: '3.0', reference: '0.37.3-3.1');
deb_check(prefix: 'libecpg3', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'libpgperl', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'libpgsql2', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'libpgtcl', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'odbc-postgresql', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'pgaccess', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'postgresql', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'postgresql-client', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'postgresql-contrib', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'postgresql-dev', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'postgresql-doc', release: '3.0', reference: '7.2.1-2woody2');
deb_check(prefix: 'python-pygresql', release: '3.0', reference: '7.2.1-2woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
