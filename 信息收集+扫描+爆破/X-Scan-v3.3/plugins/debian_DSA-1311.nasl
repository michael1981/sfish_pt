# This script was automatically generated from the dsa-1311
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25555);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1311");
 script_cve_id("CVE-2007-2138");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1311 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the PostgreSQL database performs insufficient
validation of variables passed to privileged SQL statement called
<q>security definers</q>, which could lead to SQL privilege escalation.
For the oldstable distribution (sarge) this problem has been fixed in
version 7.4.7-6sarge5. A powerpc build is not yet available due to
problems with the build host. It will be provided later.
For the stable distribution (etch) this problem has been fixed in
version 7.4.17-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1311');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your PostgreSQL packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1311] DSA-1311-1 postgresql-7.4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1311-1 postgresql-7.4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libecpg-dev', release: '3.1', reference: '7.4.7-6sarge5');
deb_check(prefix: 'libecpg4', release: '3.1', reference: '7.4.7-6sarge5');
deb_check(prefix: 'libpgtcl', release: '3.1', reference: '7.4.7-6sarge5');
deb_check(prefix: 'libpgtcl-dev', release: '3.1', reference: '7.4.7-6sarge5');
deb_check(prefix: 'libpq3', release: '3.1', reference: '7.4.7-6sarge5');
deb_check(prefix: 'postgresql', release: '3.1', reference: '7.4.7-6sarge5');
deb_check(prefix: 'postgresql-client', release: '3.1', reference: '7.4.7-6sarge5');
deb_check(prefix: 'postgresql-contrib', release: '3.1', reference: '7.4.7-6sarge5');
deb_check(prefix: 'postgresql-dev', release: '3.1', reference: '7.4.7-6sarge5');
deb_check(prefix: 'postgresql-doc', release: '3.1', reference: '7.4.7-6sarge5');
deb_check(prefix: 'postgresql-7.4', release: '4.0', reference: '7.4.17-0etch1');
deb_check(prefix: 'postgresql-client-7.4', release: '4.0', reference: '7.4.17-0etch1');
deb_check(prefix: 'postgresql-contrib-7.4', release: '4.0', reference: '7.4.17-0etch1');
deb_check(prefix: 'postgresql-doc-7.4', release: '4.0', reference: '7.4.17-0etch1');
deb_check(prefix: 'postgresql-plperl-7.4', release: '4.0', reference: '7.4.17-0etch1');
deb_check(prefix: 'postgresql-plpython-7.4', release: '4.0', reference: '7.4.17-0etch1');
deb_check(prefix: 'postgresql-pltcl-7.4', release: '4.0', reference: '7.4.17-0etch1');
deb_check(prefix: 'postgresql-server-dev-7.4', release: '4.0', reference: '7.4.17-0etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
