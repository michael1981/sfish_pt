# This script was automatically generated from the dsa-419
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15256);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "419");
 script_cve_id("CVE-2004-0016", "CVE-2004-0017");
 script_bugtraq_id(9386, 9387);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-419 security update');
 script_set_attribute(attribute: 'description', value:
'The authors of phpgroupware, a web based groupware system written in
PHP, discovered several vulnerabilities.  The Common Vulnerabilities
and Exposures project identifies the following problems:
In the "calendar" module, "save extension" was not enforced for
  holiday files.  As a result, server-side php scripts may be placed
  in directories that then could be accessed remotely and cause the
  webserver to execute those.  This was resolved by enforcing the
  extension ".txt" for holiday files.
Some SQL injection problems (non-escaping of values used in SQL
  strings) the "calendar" and "infolog" modules.
Additionally, the Debian maintainer adjusted the permissions on world
writable directories that were accidentally created by former postinst
during the installation.
For the stable distribution (woody) this problem has been fixed in
version 0.9.14-0.RC3.2.woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-419');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpgroupware, phpgroupware-calendar
and phpgroupware-infolog packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA419] DSA-419-1 phpgroupware");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-419-1 phpgroupware");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpgroupware', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-addressbook', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-admin', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-api', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-api-doc', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-bookkeeping', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-bookmarks', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-brewer', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-calendar', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-chat', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-chora', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-comic', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-core', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-core-doc', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-developer-tools', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-dj', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-eldaptir', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-email', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-filemanager', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-forum', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-ftp', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-headlines', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-hr', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-img', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-infolog', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-inv', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-manual', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-messenger', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-napster', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-news-admin', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-nntp', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-notes', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-phonelog', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-phpsysinfo', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-phpwebhosting', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-polls', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-preferences', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-projects', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-registration', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-setup', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-skel', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-soap', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-stocks', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-todo', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-tts', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-wap', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-weather', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
deb_check(prefix: 'phpgroupware-xmlrpc', release: '3.0', reference: '0.9.14-0.RC3.2.woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
