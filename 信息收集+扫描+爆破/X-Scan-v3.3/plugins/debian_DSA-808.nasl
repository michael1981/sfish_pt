# This script was automatically generated from the dsa-808
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19683);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "808");
 script_cve_id("CVE-2005-2411");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-808 security update');
 script_set_attribute(attribute: 'description', value:
'Yutaka Oiwa and Hiromitsu Takagi discovered a Cross-Site Request
Forgery (CSRF) vulnerability in tdiary, a new generation weblog that
can be exploited by remote attackers to alter the users information.
The old stable distribution (woody) does not contain tdiary packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.1-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-808');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tdiary packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA808] DSA-808-1 tdiary");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-808-1 tdiary");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tdiary', release: '3.1', reference: '2.0.1-1sarge1');
deb_check(prefix: 'tdiary-contrib', release: '3.1', reference: '2.0.1-1sarge1');
deb_check(prefix: 'tdiary-mode', release: '3.1', reference: '2.0.1-1sarge1');
deb_check(prefix: 'tdiary-plugin', release: '3.1', reference: '2.0.1-1sarge1');
deb_check(prefix: 'tdiary-theme', release: '3.1', reference: '2.0.1-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
