# This script was automatically generated from the dsa-1309
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25531);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1309");
 script_cve_id("CVE-2007-2138");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1309 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the PostgreSQL database performs insufficient
validation of variables passed to privileged SQL statements, so called
<q>security definers</q>, which could lead to SQL privilege escalation.
The oldstable distribution (sarge) doesn\'t contain PostgreSQL 8.1.
For the stable distribution (etch) this problem has been fixed in
version 8.1.9-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1309');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your PostgreSQL packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1309] DSA-1309-1 postgresql-8.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1309-1 postgresql-8.1");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libecpg-compat2', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'libecpg-dev', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'libecpg5', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'libpgtypes2', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'libpq-dev', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'libpq4', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'postgresql-8.1', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'postgresql-client-8.1', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'postgresql-contrib-8.1', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'postgresql-doc-8.1', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'postgresql-plperl-8.1', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'postgresql-plpython-8.1', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'postgresql-pltcl-8.1', release: '4.0', reference: '8.1.9-0etch1');
deb_check(prefix: 'postgresql-server-dev-8.1', release: '4.0', reference: '8.1.9-0etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
