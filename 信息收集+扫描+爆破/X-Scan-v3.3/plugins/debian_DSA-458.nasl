# This script was automatically generated from the dsa-458
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15295);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "458");
 script_cve_id("CVE-2004-0150");
 script_bugtraq_id(9836);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-458 security update');
 script_set_attribute(attribute: 'description', value:
'This security advisory corrects DSA 458-2 which caused a problem in
the gethostbyaddr routine.
The original advisory said:
Sebastian Schmidt discovered a buffer overflow bug in Python\'s
getaddrinfo function, which could allow an IPv6 address, supplied by a
remote attacker via DNS, to overwrite memory on the stack.
This bug only exists in python 2.2 and 2.2.1, and only when IPv6
support is disabled.  The python2.2 package in Debian woody meets
these conditions (the \'python\' package does not).
For the stable distribution (woody), this bug has been fixed in
version 2.2.1-4.6.
The testing and unstable distribution (sarge and sid) are not
affected by this problem.
We recommend that you update your python2.2 packages.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-458');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-458
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA458] DSA-458-3 python2.2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-458-3 python2.2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'idle-python2.2', release: '3.0', reference: '2.2.1-4.6');
deb_check(prefix: 'python2.2', release: '3.0', reference: '2.2.1-4.6');
deb_check(prefix: 'python2.2-dev', release: '3.0', reference: '2.2.1-4.6');
deb_check(prefix: 'python2.2-doc', release: '3.0', reference: '2.2.1-4.6');
deb_check(prefix: 'python2.2-elisp', release: '3.0', reference: '2.2.1-4.6');
deb_check(prefix: 'python2.2-examples', release: '3.0', reference: '2.2.1-4.6');
deb_check(prefix: 'python2.2-gdbm', release: '3.0', reference: '2.2.1-4.6');
deb_check(prefix: 'python2.2-mpz', release: '3.0', reference: '2.2.1-4.6');
deb_check(prefix: 'python2.2-tk', release: '3.0', reference: '2.2.1-4.6');
deb_check(prefix: 'python2.2-xmlbase', release: '3.0', reference: '2.2.1-4.6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
