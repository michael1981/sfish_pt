# This script was automatically generated from the dsa-683
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16465);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "683");
 script_cve_id("CVE-2005-0245", "CVE-2005-0247");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-683 security update');
 script_set_attribute(attribute: 'description', value:
'Several buffer overflows have been discovered in PL/PgSQL as part of
the PostgreSQL engine which could lead to the execution of arbitrary
code.
For the stable distribution (woody) these problems have been fixed in
version 7.2.1-2woody8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-683');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your postgresql packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA683] DSA-683-1 postgresql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-683-1 postgresql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libecpg3', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'libpgperl', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'libpgsql2', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'libpgtcl', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'odbc-postgresql', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'pgaccess', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'postgresql', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'postgresql-client', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'postgresql-contrib', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'postgresql-dev', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'postgresql-doc', release: '3.0', reference: '7.2.1-2woody8');
deb_check(prefix: 'python-pygresql', release: '3.0', reference: '7.2.1-2woody8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
