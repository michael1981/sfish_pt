# This script was automatically generated from the dsa-347
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15184);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "347");
 script_cve_id("CVE-2003-0515");
 script_bugtraq_id(8146);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-347 security update');
 script_set_attribute(attribute: 'description', value:
'teapop, a POP-3 server, includes modules for authenticating users
against a PostgreSQL or MySQL database.  These modules do not properly
escape user-supplied strings before using them in SQL queries.  This
vulnerability could be exploited to execute arbitrary SQL code under the
privileges of the database user as which teapop has authenticated.
For the stable distribution (woody) this problem has been fixed in
version 0.3.4-1woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-347');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-347
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA347] DSA-347-1 teapop");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-347-1 teapop");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'teapop', release: '3.0', reference: '0.3.4-1woody2');
deb_check(prefix: 'teapop-mysql', release: '3.0', reference: '0.3.4-1woody2');
deb_check(prefix: 'teapop-pgsql', release: '3.0', reference: '0.3.4-1woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
