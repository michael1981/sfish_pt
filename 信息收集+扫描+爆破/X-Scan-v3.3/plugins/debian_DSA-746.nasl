# This script was automatically generated from the dsa-746
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19195);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "746");
 script_cve_id("CVE-2005-1921");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-746 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability had been identified in the xmlrpc library included with
phpgroupware, a web-based application including email, calendar and
other groupware functionality. This vulnerability could lead to the
execution of arbitrary commands on the server running phpgroupware.
The security team is continuing to investigate the version of
phpgroupware included with the old stable distribution (woody). At this
time we recommend disabling phpgroupware or upgrading to the current
stable distribution (sarge).
For the current stable distribution (sarge) this problem has been fixed
in version 0.9.16.005-3.sarge0.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-746');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpgroupware package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA746] DSA-746-1 phpgroupware");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-746-1 phpgroupware");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpgroupware', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-addressbook', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-admin', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-bookmarks', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-calendar', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-chat', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-comic', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-core', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-developer-tools', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-dj', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-eldaptir', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-email', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-etemplate', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-felamimail', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-filemanager', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-folders', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-forum', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-ftp', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-fudforum', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-headlines', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-hr', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-img', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-infolog', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-manual', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-messenger', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-news-admin', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-nntp', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-notes', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-phonelog', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-phpbrain', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-phpgwapi', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-phpsysinfo', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-polls', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-preferences', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-projects', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-qmailldap', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-registration', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-setup', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-sitemgr', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-skel', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-soap', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-stocks', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-todo', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-tts', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-wiki', release: '3.1', reference: '0.9.16.005-3.sarge0');
deb_check(prefix: 'phpgroupware-xmlrpc', release: '3.1', reference: '0.9.16.005-3.sarge0');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
