# This script was automatically generated from the dsa-577
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15675);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "577");
 script_cve_id("CVE-2004-0977");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-577 security update');
 script_set_attribute(attribute: 'description', value:
'Trustix Security Engineers identified insecure temporary file creation
in a script included in the postgresql suite, an object-relational SQL
database.  This could lead an attacker to trick a user to overwrite
arbitrary files he has write access to.
For the stable distribution (woody) this problem has been fixed in
version 7.2.1-2woody6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-577');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your postgresql packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA577] DSA-577-1 postgresql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-577-1 postgresql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libecpg3', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'libpgperl', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'libpgsql2', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'libpgtcl', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'odbc-postgresql', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'pgaccess', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'postgresql', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'postgresql-client', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'postgresql-contrib', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'postgresql-dev', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'postgresql-doc', release: '3.0', reference: '7.2.1-2woody6');
deb_check(prefix: 'python-pygresql', release: '3.0', reference: '7.2.1-2woody6');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
