# This script was automatically generated from the dsa-560
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15658);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "560");
 script_cve_id("CVE-2004-0687", "CVE-2004-0688");
 script_xref(name: "CERT", value: "537878");
 script_xref(name: "CERT", value: "882750");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-560 security update');
 script_set_attribute(attribute: 'description', value:
'Chris Evans discovered several stack and integer overflows in the
libXpm library which is included in LessTif.
For the stable distribution (woody) this problem has been fixed in
version 0.93.18-5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-560');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lesstif packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA560] DSA-560-1 lesstif1-1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-560-1 lesstif1-1");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lesstif-bin', release: '3.0', reference: '0.93.18-5');
deb_check(prefix: 'lesstif-dbg', release: '3.0', reference: '0.93.18-5');
deb_check(prefix: 'lesstif-dev', release: '3.0', reference: '0.93.18-5');
deb_check(prefix: 'lesstif-doc', release: '3.0', reference: '0.93.18-5');
deb_check(prefix: 'lesstif1', release: '3.0', reference: '0.93.18-5');
deb_check(prefix: 'lesstif1-1', release: '3.0', reference: '0.93.18-5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
