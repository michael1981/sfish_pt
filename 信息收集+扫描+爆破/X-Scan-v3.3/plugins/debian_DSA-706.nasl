# This script was automatically generated from the dsa-706
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18030);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "706");
 script_cve_id("CVE-2005-0390");
 script_bugtraq_id(13059);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-706 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar from the Debian Security Audit Project discovered a
buffer overflow in axel, a light download accelerator.  When reading
remote input the program did not check if a part of the input can
overflow a buffer and maybe trigger the execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 1.0a-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-706');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your axel package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA706] DSA-706-1 axel");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-706-1 axel");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'axel', release: '3.0', reference: '1.0a-1woody1');
deb_check(prefix: 'axel-kapt', release: '3.0', reference: '1.0a-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
