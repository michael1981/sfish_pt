# This script was automatically generated from the dsa-1556
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32057);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1556");
 script_cve_id("CVE-2008-1927");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1556 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered that the Perl interpreter may encounter a buffer
overflow condition when compiling certain regular expressions containing
Unicode characters.  This also happens if the offending characters are
contained in a variable reference protected by the \\Q...\\E quoting
construct.  When encountering this condition, the Perl interpreter
typically crashes, but arbitrary code execution cannot be ruled out.
For the stable distribution (etch), this problem has been fixed in
version 5.8.8-7etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1556');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your perl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1556] DSA-1556-2 perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1556-2 perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libcgi-fast-perl', release: '4.0', reference: '5.8.8-7etch3');
deb_check(prefix: 'libperl-dev', release: '4.0', reference: '5.8.8-7etch3');
deb_check(prefix: 'libperl5.8', release: '4.0', reference: '5.8.8-7etch3');
deb_check(prefix: 'perl', release: '4.0', reference: '5.8.8-7etch3');
deb_check(prefix: 'perl-base', release: '4.0', reference: '5.8.8-7etch3');
deb_check(prefix: 'perl-debug', release: '4.0', reference: '5.8.8-7etch3');
deb_check(prefix: 'perl-doc', release: '4.0', reference: '5.8.8-7etch3');
deb_check(prefix: 'perl-modules', release: '4.0', reference: '5.8.8-7etch3');
deb_check(prefix: 'perl-suid', release: '4.0', reference: '5.8.8-7etch3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
