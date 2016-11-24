# This script was automatically generated from the dsa-1398
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27628);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1398");
 script_cve_id("CVE-2007-5740");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1398 security update');
 script_set_attribute(attribute: 'description', value:
'Bernhard Mueller of SEC Consult has discovered a format string
vulnerability in perdition, an IMAP proxy.  This vulnerability could
allow an unauthenticated remote user to run arbitrary code on the
perdition server by providing a specially formatted IMAP tag.


For the old stable distribution (sarge), this problem has been fixed in
version 1.15-5sarge1.


For the stable distribution (etch), this problem has been fixed in
version 1.17-7etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1398');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your perdition package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1398] DSA-1398-1 perdition");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1398-1 perdition");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'perdition', release: '3.1', reference: '1.15-5sarge1');
deb_check(prefix: 'perdition-dev', release: '3.1', reference: '1.15-5sarge1');
deb_check(prefix: 'perdition-ldap', release: '3.1', reference: '1.15-5sarge1');
deb_check(prefix: 'perdition-mysql', release: '3.1', reference: '1.15-5sarge1');
deb_check(prefix: 'perdition-odbc', release: '3.1', reference: '1.15-5sarge1');
deb_check(prefix: 'perdition-postgresql', release: '3.1', reference: '1.15-5sarge1');
deb_check(prefix: 'perdition', release: '4.0', reference: '1.17-7etch1');
deb_check(prefix: 'perdition-dev', release: '4.0', reference: '1.17-7etch1');
deb_check(prefix: 'perdition-ldap', release: '4.0', reference: '1.17-7etch1');
deb_check(prefix: 'perdition-mysql', release: '4.0', reference: '1.17-7etch1');
deb_check(prefix: 'perdition-odbc', release: '4.0', reference: '1.17-7etch1');
deb_check(prefix: 'perdition-postgresql', release: '4.0', reference: '1.17-7etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
