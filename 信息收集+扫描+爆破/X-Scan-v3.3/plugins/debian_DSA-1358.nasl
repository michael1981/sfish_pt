# This script was automatically generated from the dsa-1358
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25938);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1358");
 script_cve_id("CVE-2007-1306", "CVE-2007-1561", "CVE-2007-2294", "CVE-2007-2297", "CVE-2007-2488", "CVE-2007-3762", "CVE-2007-3763");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1358 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Asterisk, a free
software PBX and telephony toolkit. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2007-1306
    <q>Mu Security</q> discovered that a NULL pointer dereference in the SIP
    implementation could lead to denial of service.
CVE-2007-1561
    Inria Lorraine discovered that a programming error in the SIP
    implementation could lead to denial of service.
CVE-2007-2294
    It was discovered that a NULL pointer dereference in the manager
    interface could lead to denial of service.
CVE-2007-2297
    It was discovered that a programming error in the SIP implementation
    could lead to denial of service.
CVE-2007-2488
    Tim Panton and Birgit Arkestein discovered that a programming error
    in the IAX2 implementation could lead to information disclosure.
CVE-2007-3762
    Russell Bryant discovered that a buffer overflow in the IAX
    implementation could lead to the execution of arbitrary code.
CVE-2007-3763
    Chris Clark and Zane Lackey discovered that several NULL pointer
    dereferences in the IAX2 implementation could lead to denial of
    service.
CVE-2007-3764
    Will Drewry discovered that a programming error in the Skinny
    implementation could lead to denial of service.
For the oldstable distribution (sarge) these problems have been fixed in
version 1.0.7.dfsg.1-2sarge5.
For the stable distribution (etch) these problems have been fixed
in version 1:1.2.13~dfsg-2etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1358');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Asterisk packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1358] DSA-1358-1 asterisk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1358-1 asterisk");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'asterisk', release: '3.1', reference: '1.0.7.dfsg.1-2sarge5');
deb_check(prefix: 'asterisk-config', release: '3.1', reference: '1.0.7.dfsg.1-2sarge5');
deb_check(prefix: 'asterisk-dev', release: '3.1', reference: '1.0.7.dfsg.1-2sarge5');
deb_check(prefix: 'asterisk-doc', release: '3.1', reference: '1.0.7.dfsg.1-2sarge5');
deb_check(prefix: 'asterisk-gtk-console', release: '3.1', reference: '1.0.7.dfsg.1-2sarge5');
deb_check(prefix: 'asterisk-h323', release: '3.1', reference: '1.0.7.dfsg.1-2sarge5');
deb_check(prefix: 'asterisk-sounds-main', release: '3.1', reference: '1.0.7.dfsg.1-2sarge5');
deb_check(prefix: 'asterisk-web-vmail', release: '3.1', reference: '1.0.7.dfsg.1-2sarge5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
