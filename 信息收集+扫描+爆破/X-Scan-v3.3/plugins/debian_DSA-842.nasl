# This script was automatically generated from the dsa-842
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19846);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "842");
 script_cve_id("CVE-2005-2498");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-842 security update');
 script_set_attribute(attribute: 'description', value:
'Stefan Esser discovered a vulnerability in the XML-RPC libraries which
are also present in egroupware, a web-based groupware suite, that
allows injection of arbitrary PHP code into eval() statements.
The old stable distribution (woody) does not contain egroupware packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.0.007-2.dfsg-2sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-842');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your egroupware packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA842] DSA-842-1 egroupware");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-842-1 egroupware");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'egroupware', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-addressbook', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-bookmarks', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-calendar', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-comic', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-core', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-developer-tools', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-email', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-emailadmin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-etemplate', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-felamimail', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-filemanager', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-forum', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-ftp', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-fudforum', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-headlines', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-infolog', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-jinn', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-ldap', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-manual', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-messenger', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-news-admin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-phpbrain', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-phpldapadmin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-phpsysinfo', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-polls', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-projects', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-registration', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-sitemgr', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-stocks', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-tts', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
deb_check(prefix: 'egroupware-wiki', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
