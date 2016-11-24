# This script was automatically generated from the dsa-1012
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22554);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1012");
 script_cve_id("CVE-2005-4667");
 script_bugtraq_id(15968);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1012 security update');
 script_set_attribute(attribute: 'description', value:
'A buffer overflow in the command line argument parsing has been
discovered in unzip, the de-archiver for ZIP files, that could lead to
the execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 5.50-1woody6.
For the stable distribution (sarge) this problem has been fixed in
version 5.52-1sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1012');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your unzip package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1012] DSA-1012-1 unzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1012-1 unzip");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'unzip', release: '3.0', reference: '5.50-1woody6');
deb_check(prefix: 'unzip', release: '3.1', reference: '5.52-1sarge4');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
