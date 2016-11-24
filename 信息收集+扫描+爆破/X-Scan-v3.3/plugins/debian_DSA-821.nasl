# This script was automatically generated from the dsa-821
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19790);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "821");
 script_cve_id("CVE-2005-2491");
 script_bugtraq_id(14620);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-821 security update');
 script_set_attribute(attribute: 'description', value:
'An integer overflow with a subsequent buffer overflow has been detected
in PCRE, the Perl Compatible Regular Expressions library, which allows
an attacker to execute arbitrary code, and is also present in Python.
Exploiting this vulnerability requires an attacker to specify the used
regular expression.
The old stable distribution (woody) does not contain python2.3 packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.3.5-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-821');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your python2.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA821] DSA-821-1 python2.3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-821-1 python2.3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'idle-python2.3', release: '3.1', reference: '2.3.5-3sarge1');
deb_check(prefix: 'python2.3', release: '3.1', reference: '2.3.5-3sarge1');
deb_check(prefix: 'python2.3-dev', release: '3.1', reference: '2.3.5-3sarge1');
deb_check(prefix: 'python2.3-doc', release: '3.1', reference: '2.3.5-3sarge1');
deb_check(prefix: 'python2.3-examples', release: '3.1', reference: '2.3.5-3sarge1');
deb_check(prefix: 'python2.3-gdbm', release: '3.1', reference: '2.3.5-3sarge1');
deb_check(prefix: 'python2.3-mpz', release: '3.1', reference: '2.3.5-3sarge1');
deb_check(prefix: 'python2.3-tk', release: '3.1', reference: '2.3.5-3sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
