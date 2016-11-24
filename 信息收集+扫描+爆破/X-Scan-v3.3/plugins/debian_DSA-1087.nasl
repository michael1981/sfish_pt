# This script was automatically generated from the dsa-1087
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22629);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1087");
 script_cve_id("CVE-2006-2313", "CVE-2006-2314");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1087 security update');
 script_set_attribute(attribute: 'description', value:
'Several encoding problems have been discovered in PostgreSQL, a
popular SQL database.  The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2006-2313
    Akio Ishida and Yasuo Ohgaki discovered a weakness in the handling
    of invalidly-encoded multibyte text data which could allow an
    attacker to inject arbitrary SQL commands.
CVE-2006-2314
    A similar problem exists in client-side encodings (such as SJIS,
    BIG5, GBK, GB18030, and UHC) which contain valid multibyte
    characters that end with the backslash character.  An attacker
    could supply a specially crafted byte sequence that is able to
    inject arbitrary SQL commands.
    This issue does not affect you if you only use single-byte (like
    SQL_ASCII or the ISO-8859-X family) or unaffected multibyte (like
    UTF-8) encodings.
    psycopg and python-pgsql use the old encoding for binary data and
    may have to be updated.
The old stable distribution (woody) is affected by these problems but
we\'re unable to correct the package.
For the stable distribution (sarge) these problems have been fixed in
version 7.4.7-6sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1087');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your postgresql packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1087] DSA-1087-1 postgresql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1087-1 postgresql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libecpg-dev', release: '3.1', reference: '7.4.7-6sarge2');
deb_check(prefix: 'libecpg4', release: '3.1', reference: '7.4.7-6sarge2');
deb_check(prefix: 'libpgtcl', release: '3.1', reference: '7.4.7-6sarge2');
deb_check(prefix: 'libpgtcl-dev', release: '3.1', reference: '7.4.7-6sarge2');
deb_check(prefix: 'libpq3', release: '3.1', reference: '7.4.7-6sarge2');
deb_check(prefix: 'postgresql', release: '3.1', reference: '7.4.7-6sarge2');
deb_check(prefix: 'postgresql-client', release: '3.1', reference: '7.4.7-6sarge2');
deb_check(prefix: 'postgresql-contrib', release: '3.1', reference: '7.4.7-6sarge2');
deb_check(prefix: 'postgresql-dev', release: '3.1', reference: '7.4.7-6sarge2');
deb_check(prefix: 'postgresql-doc', release: '3.1', reference: '7.4.7-6sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
