# This script was automatically generated from the dsa-798
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19568);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "798");
 script_cve_id("CVE-2005-2498", "CVE-2005-2600", "CVE-2005-2761");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-798 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in phpgroupware, a web
based groupware system written in PHP.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Stefan Esser discovered another vulnerability in the XML-RPC
    libraries that allows injection of arbitrary PHP code into eval()
    statements.  The XMLRPC component has been disabled.
    Alexander Heidenreich discovered a cross-site scripting problem
    in the tree view of FUD Forum Bulletin Board Software, which is
    also present in phpgroupware.
    A global cross-site scripting fix has also been included that
    protects against potential malicious scripts embedded in CSS and
    xmlns in various parts of the application and modules.
This update also contains a postinst bugfix that has been approved for
the next update to the stable release.
For the old stable distribution (woody) these problems don\'t apply.
For the stable distribution (sarge) these problems have been fixed in
version 0.9.16.005-3.sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-798');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpgroupware packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA798] DSA-798-1 phpgroupware");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-798-1 phpgroupware");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpgroupware', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-addressbook', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-admin', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-bookmarks', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-calendar', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-chat', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-comic', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-core', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-developer-tools', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-dj', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-eldaptir', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-email', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-etemplate', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-felamimail', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-filemanager', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-folders', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-forum', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-ftp', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-fudforum', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-headlines', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-hr', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-img', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-infolog', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-manual', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-messenger', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-news-admin', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-nntp', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-notes', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-phonelog', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-phpbrain', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-phpgwapi', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-phpsysinfo', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-polls', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-preferences', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-projects', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-qmailldap', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-registration', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-setup', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-sitemgr', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-skel', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-soap', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-stocks', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-todo', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-tts', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-wiki', release: '3.1', reference: '0.9.16.005-3.sarge2');
deb_check(prefix: 'phpgroupware-xmlrpc', release: '3.1', reference: '0.9.16.005-3.sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
