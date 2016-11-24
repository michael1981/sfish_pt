# This script was automatically generated from the dsa-1229
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23790);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1229");
 script_cve_id("CVE-2006-5444");
 script_bugtraq_id(20617);
 script_xref(name: "CERT", value: "521252");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1229 security update');
 script_set_attribute(attribute: 'description', value:
'Adam Boileau discovered an integer overflow in the Skinny channel
driver in Asterisk, an Open Source Private Branch Exchange or
telephone system, as used by Cisco SCCP phones, which allows remote
attackers to execute arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.7.dfsg.1-2sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1229');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your asterisk packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1229] DSA-1229-1 asterisk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1229-1 asterisk");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'asterisk', release: '3.1', reference: '1.0.7.dfsg.1-2sarge4');
deb_check(prefix: 'asterisk-config', release: '3.1', reference: '1.0.7.dfsg.1-2sarge4');
deb_check(prefix: 'asterisk-dev', release: '3.1', reference: '1.0.7.dfsg.1-2sarge4');
deb_check(prefix: 'asterisk-doc', release: '3.1', reference: '1.0.7.dfsg.1-2sarge4');
deb_check(prefix: 'asterisk-gtk-console', release: '3.1', reference: '1.0.7.dfsg.1-2sarge4');
deb_check(prefix: 'asterisk-h323', release: '3.1', reference: '1.0.7.dfsg.1-2sarge4');
deb_check(prefix: 'asterisk-sounds-main', release: '3.1', reference: '1.0.7.dfsg.1-2sarge4');
deb_check(prefix: 'asterisk-web-vmail', release: '3.1', reference: '1.0.7.dfsg.1-2sarge4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
