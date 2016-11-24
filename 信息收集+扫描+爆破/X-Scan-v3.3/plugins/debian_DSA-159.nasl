# This script was automatically generated from the dsa-159
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14996);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "159");
 script_cve_id("CVE-2002-1119");
 script_bugtraq_id(5581);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-159 security update');
 script_set_attribute(attribute: 'description', value:
'Zack Weinberg discovered an insecure use of a temporary file in
os._execvpe from os.py.  It uses a predictable name which could lead
execution of arbitrary code.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-159');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Python packages immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA159] DSA-159-1 python");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-159-1 python");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'idle', release: '2.2', reference: '1.5.2-10potato13');
deb_check(prefix: 'python-base', release: '2.2', reference: '1.5.2-10potato13');
deb_check(prefix: 'python-dev', release: '2.2', reference: '1.5.2-10potato13');
deb_check(prefix: 'python-elisp', release: '2.2', reference: '1.5.2-10potato13');
deb_check(prefix: 'python-examples', release: '2.2', reference: '1.5.2-10potato13');
deb_check(prefix: 'python-gdbm', release: '2.2', reference: '1.5.2-10potato13');
deb_check(prefix: 'python-mpz', release: '2.2', reference: '1.5.2-10potato13');
deb_check(prefix: 'python-regrtest', release: '2.2', reference: '1.5.2-10potato13');
deb_check(prefix: 'python-tk', release: '2.2', reference: '1.5.2-10potato13');
deb_check(prefix: 'python-zlib', release: '2.2', reference: '1.5.2-10potato13');
deb_check(prefix: 'idle', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'idle-python1.5', release: '3.0', reference: '1.5.2-23.2');
deb_check(prefix: 'idle-python2.1', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'idle-python2.2', release: '3.0', reference: '2.2.1-4.2');
deb_check(prefix: 'python', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python-dev', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python-doc', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python-elisp', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python-examples', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python-gdbm', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python-mpz', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python-tk', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python-xmlbase', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python1.5', release: '3.0', reference: '1.5.2-23.2');
deb_check(prefix: 'python1.5-dev', release: '3.0', reference: '1.5.2-23.2');
deb_check(prefix: 'python1.5-examples', release: '3.0', reference: '1.5.2-23.2');
deb_check(prefix: 'python1.5-gdbm', release: '3.0', reference: '1.5.2-23.2');
deb_check(prefix: 'python1.5-mpz', release: '3.0', reference: '1.5.2-23.2');
deb_check(prefix: 'python1.5-tk', release: '3.0', reference: '1.5.2-23.2');
deb_check(prefix: 'python2.1', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python2.1-dev', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python2.1-doc', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python2.1-elisp', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python2.1-examples', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python2.1-gdbm', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python2.1-mpz', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python2.1-tk', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python2.1-xmlbase', release: '3.0', reference: '2.1.3-3.2');
deb_check(prefix: 'python2.2', release: '3.0', reference: '2.2.1-4.2');
deb_check(prefix: 'python2.2-dev', release: '3.0', reference: '2.2.1-4.2');
deb_check(prefix: 'python2.2-doc', release: '3.0', reference: '2.2.1-4.2');
deb_check(prefix: 'python2.2-elisp', release: '3.0', reference: '2.2.1-4.2');
deb_check(prefix: 'python2.2-examples', release: '3.0', reference: '2.2.1-4.2');
deb_check(prefix: 'python2.2-gdbm', release: '3.0', reference: '2.2.1-4.2');
deb_check(prefix: 'python2.2-mpz', release: '3.0', reference: '2.2.1-4.2');
deb_check(prefix: 'python2.2-tk', release: '3.0', reference: '2.2.1-4.2');
deb_check(prefix: 'python2.2-xmlbase', release: '3.0', reference: '2.2.1-4.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
