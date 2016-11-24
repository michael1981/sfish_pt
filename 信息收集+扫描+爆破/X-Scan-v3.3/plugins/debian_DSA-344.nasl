# This script was automatically generated from the dsa-344
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15181);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "344");
 script_cve_id("CVE-2003-0282");
 script_bugtraq_id(7550);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-344 security update');
 script_set_attribute(attribute: 'description', value:
'A directory traversal vulnerability in UnZip 5.50 allows attackers to
bypass a check for relative pathnames ("../") by placing certain invalid
characters between the two "." characters.  The fix which was
implemented in DSA-344-1 may not have protected against all methods of
exploiting this vulnerability.
For the stable distribution (woody) this problem has been fixed in
version 5.50-1woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-344');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-344
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA344] DSA-344-2 unzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-344-2 unzip");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'unzip', release: '3.0', reference: '5.50-1woody2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
