# This script was automatically generated from the dsa-1020
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22562);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1020");
 script_cve_id("CVE-2006-0459");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1020 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Moore discovered that flex, a scanner generator, generates code,
which allocates insufficient memory, if the grammar contains REJECT
statements or trailing context rules. This may lead to a buffer overflow
and the execution of arbitrary code.
If you use code, which is derived from a vulnerable lex grammar in
an untrusted environment you need to regenerate your scanner with the
fixed version of flex.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.5.31-31sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1020');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your flex package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1020] DSA-1020-1 flex");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1020-1 flex");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'flex', release: '3.1', reference: '2.5.31-31sarge1');
deb_check(prefix: 'flex-doc', release: '3.1', reference: '2.5.31-31sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
