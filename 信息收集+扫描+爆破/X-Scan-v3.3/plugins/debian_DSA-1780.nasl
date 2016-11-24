# This script was automatically generated from the dsa-1780
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38202);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1780");
 script_cve_id("CVE-2009-0663", "CVE-2009-1341");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1780 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been discovered in libdbd-pg-perl, the DBI
driver module for PostgreSQL database access (DBD::Pg).
CVE-2009-0663
  A heap-based buffer overflow may allow attackers to execute arbitrary
  code through applications which read rows from the database using the
  pg_getline and getline functions.  (More common retrieval methods,
  such as selectall_arrayref and fetchrow_array, are not affected.)
CVE-2009-1341
  A memory leak in the routine which unquotes BYTEA values returned from
  the database allows attackers to cause a denial of service.
For the old stable distribution (etch), these problems have been fixed
in version 1.49-2+etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1780');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libdbd-pg-perl package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1780] DSA-1780-1 libdbd-pg-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1780-1 libdbd-pg-perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libdbd-pg-perl', release: '4.0', reference: '1.49-2+etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
