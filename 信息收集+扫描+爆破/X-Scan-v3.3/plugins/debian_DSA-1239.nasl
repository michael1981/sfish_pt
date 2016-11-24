# This script was automatically generated from the dsa-1239
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23913);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1239");
 script_cve_id("CVE-2006-4244", "CVE-2006-4731", "CVE-2006-5872");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1239 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in SQL Ledger, a web
based double-entry accounting program, which may lead to the execution
of arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2006-4244
    Chris Travers discovered that the session management can be tricked
    into hijacking existing sessions.
CVE-2006-4731
    Chris Travers discovered that directory traversal vulnerabilities
    can be exploited to execute arbitrary Perl code.
CVE-2006-5872
    It was discovered that missing input sanitising allows execution of
    arbitrary Perl code.
For the stable distribution (sarge) these problems have been fixed in
version 2.4.7-2sarge1.
For the upcoming stable distribution (etch) these problems have been
fixed in version 2.6.21-1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1239');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sql-ledger packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1239] DSA-1239-1 sql-ledger");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1239-1 sql-ledger");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sql-ledger', release: '3.1', reference: '2.4.7-2sarge1');
deb_check(prefix: 'sql-ledger', release: '4.0', reference: '2.6.21-1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
