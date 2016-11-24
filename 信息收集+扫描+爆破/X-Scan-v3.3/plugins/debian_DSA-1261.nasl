# This script was automatically generated from the dsa-1261
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24359);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1261");
 script_cve_id("CVE-2007-0555");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1261 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the PostgreSQL database performs insufficient type
checking for SQL function arguments, which might lead to denial of service
or information disclosure.
For the stable distribution (sarge) this problem has been fixed in
version 7.4.7-6sarge4.
For the upcoming stable distribution (etch) this problem has been
fixed in version 8.1.7-1 of the postgresql-8.1 package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1261');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your PostgreSQL packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1261] DSA-1261-1 postgresql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1261-1 postgresql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libecpg-dev', release: '3.1', reference: '7.4.7-6sarge4');
deb_check(prefix: 'libecpg4', release: '3.1', reference: '7.4.7-6sarge4');
deb_check(prefix: 'libpgtcl', release: '3.1', reference: '7.4.7-6sarge4');
deb_check(prefix: 'libpgtcl-dev', release: '3.1', reference: '7.4.7-6sarge4');
deb_check(prefix: 'libpq3', release: '3.1', reference: '7.4.7-6sarge4');
deb_check(prefix: 'postgresql', release: '3.1', reference: '7.4.7-6sarge4');
deb_check(prefix: 'postgresql-client', release: '3.1', reference: '7.4.7-6sarge4');
deb_check(prefix: 'postgresql-contrib', release: '3.1', reference: '7.4.7-6sarge4');
deb_check(prefix: 'postgresql-dev', release: '3.1', reference: '7.4.7-6sarge4');
deb_check(prefix: 'postgresql-doc', release: '3.1', reference: '7.4.7-6sarge4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
