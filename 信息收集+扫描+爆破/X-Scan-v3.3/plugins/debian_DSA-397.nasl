# This script was automatically generated from the dsa-397
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15234);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "397");
 script_cve_id("CVE-2003-0901");
 script_bugtraq_id(8741);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-397 security update');
 script_set_attribute(attribute: 'description', value:
'Tom Lane discovered a buffer overflow in the to_ascii function in
PostgreSQL.  This allows remote attackers to execute arbitrary code on
the host running the database.
For the stable distribution (woody) this problem has been fixed in
version 7.2.1-2woody4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-397');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your postgresql package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA397] DSA-397-1 postgresql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-397-1 postgresql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libecpg3', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'libpgperl', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'libpgsql2', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'libpgtcl', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'odbc-postgresql', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'pgaccess', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'postgresql', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'postgresql-client', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'postgresql-contrib', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'postgresql-dev', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'postgresql-doc', release: '3.0', reference: '7.2.1-2woody4');
deb_check(prefix: 'python-pygresql', release: '3.0', reference: '7.2.1-2woody4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
