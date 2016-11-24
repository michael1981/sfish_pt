# This script was automatically generated from the dsa-468
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15305);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "468");
 script_cve_id("CVE-2004-0152", "CVE-2004-0153");
 script_bugtraq_id(9974);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-468 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar discovered a number of vulnerabilities in emil, a
filter for converting Internet mail messages.  The vulnerabilities
fall into two categories:
   Buffer overflows in (1) the encode_mime function,
   (2) the encode_uuencode function, (3) the decode_uuencode
   function.  These bugs could allow a carefully crafted email message
   to cause the execution of arbitrary code supplied with the message
   when it is acted upon by emil.
   Format string bugs in statements which print
   various error messages.  The exploit potential of these bugs has
   not been established, and is probably configuration-dependent.
For the stable distribution (woody) these problems have been fixed in
version 2.1.0-beta9-11woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-468');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-468
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA468] DSA-468-1 emil");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-468-1 emil");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'emil', release: '3.0', reference: '2.1.0-beta9-11woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
