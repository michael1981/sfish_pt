# This script was automatically generated from the dsa-747
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18662);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "747");
 script_cve_id("CVE-2005-1921");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-747 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability has been identified in the xmlrpc library included in
the egroupware package. This vulnerability could lead to the execution
of arbitrary commands on the server running egroupware.
The old stable distribution (woody) did not include egroupware.
For the current stable distribution (sarge), this problem is fixed in
version 1.0.0.007-2.dfsg-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-747');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your egroupware package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA747] DSA-747-1 egroupware");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-747-1 egroupware");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'egroupware', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-addressbook', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-bookmarks', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-calendar', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-comic', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-core', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-developer-tools', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-email', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-emailadmin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-etemplate', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-felamimail', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-filemanager', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-forum', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-ftp', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-fudforum', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-headlines', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-infolog', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-jinn', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-ldap', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-manual', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-messenger', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-news-admin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-phpbrain', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-phpldapadmin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-phpsysinfo', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-polls', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-projects', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-registration', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-sitemgr', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-stocks', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-tts', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
deb_check(prefix: 'egroupware-wiki', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
