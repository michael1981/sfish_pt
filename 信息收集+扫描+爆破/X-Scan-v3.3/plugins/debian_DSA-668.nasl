# This script was automatically generated from the dsa-668
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16342);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "668");
 script_cve_id("CVE-2005-0227");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-668 security update');
 script_set_attribute(attribute: 'description', value:
'John Heasman and others discovered a bug in the PostgreSQL engine
which would allow any user load an arbitrary local library into it.
For the stable distribution (woody) this problem has been fixed in
version 7.2.1-2woody7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-668');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your postgresql packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA668] DSA-668-1 postgresql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-668-1 postgresql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libecpg3', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'libpgperl', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'libpgsql2', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'libpgtcl', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'odbc-postgresql', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'pgaccess', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'postgresql', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'postgresql-client', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'postgresql-contrib', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'postgresql-dev', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'postgresql-doc', release: '3.0', reference: '7.2.1-2woody7');
deb_check(prefix: 'python-pygresql', release: '3.0', reference: '7.2.1-2woody7');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
