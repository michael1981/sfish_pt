# This script was automatically generated from the dsa-1417
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29191);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1417");
 script_cve_id("CVE-2007-6170");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1417 security update');
 script_set_attribute(attribute: 'description', value:
'Tilghman Lesher discovered that the logging engine of Asterisk, a free
software PBX and telephony toolkit, performs insufficient sanitising of
call-related data, which may lead to SQL injection.
For the old stable distribution (sarge), this problem has been fixed
in version 1:1.0.7.dfsg.1-2sarge6.
For the stable distribution (etch), this problem has been fixed in
version 1:1.2.13~dfsg-2etch2. Updated packages for ia64 will be provided
later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1417');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your asterisk packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1417] DSA-1417-1 asterisk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1417-1 asterisk");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'asterisk', release: '3.1', reference: '1.0.7.dfsg.1-2sarge6');
deb_check(prefix: 'asterisk-config', release: '3.1', reference: '1.0.7.dfsg.1-2sarge6');
deb_check(prefix: 'asterisk-dev', release: '3.1', reference: '1.0.7.dfsg.1-2sarge6');
deb_check(prefix: 'asterisk-doc', release: '3.1', reference: '1.0.7.dfsg.1-2sarge6');
deb_check(prefix: 'asterisk-gtk-console', release: '3.1', reference: '1.0.7.dfsg.1-2sarge6');
deb_check(prefix: 'asterisk-h323', release: '3.1', reference: '1.0.7.dfsg.1-2sarge6');
deb_check(prefix: 'asterisk-sounds-main', release: '3.1', reference: '1.0.7.dfsg.1-2sarge6');
deb_check(prefix: 'asterisk-web-vmail', release: '3.1', reference: '1.0.7.dfsg.1-2sarge6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
