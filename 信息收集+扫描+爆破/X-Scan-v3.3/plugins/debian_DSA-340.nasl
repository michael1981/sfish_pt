# This script was automatically generated from the dsa-340
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15177);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "340");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-340 security update');
 script_set_attribute(attribute: 'description', value:
'NOTE: due to a combination of administrative problems, this advisory
was erroneously released with the identifier "DSA-338-1".  DSA-338-1
correctly refers to an earlier advisory regarding proftpd.
x-face-el, a decoder for images included inline in X-Face email
headers, does not take appropriate security precautions when creating
temporary files.  This bug could potentially be exploited to overwrite
arbitrary files with the privileges of the user running Emacs and
x-face-el, potentially with contents supplied by the attacker.
For the stable distribution (woody) this problem has been fixed in
version 1.3.6.19-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-340');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-340
and install the recommended updated packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA340] DSA-340-1 x-face-el");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-340-1 x-face-el");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'x-face-el', release: '3.0', reference: '1.3.6.19-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
