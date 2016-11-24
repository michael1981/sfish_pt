# This script was automatically generated from the dsa-899
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22765);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "899");
 script_cve_id("CVE-2005-0870", "CVE-2005-2600", "CVE-2005-3347", "CVE-2005-3348");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-899 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in egroupware, a
web-based groupware suite.  The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2005-0870
    Maksymilian Arciemowicz discovered several cross site scripting
    problems in phpsysinfo, which are also present in the imported
    version in egroupware and of which not all were fixed in DSA 724.
CVE-2005-2600
    Alexander Heidenreich discovered a cross-site scripting problem in
    the tree view of FUD Forum Bulletin Board Software, which is also
    present in egroupware and allows remote attackers to read private
    posts via a modified mid parameter.
CVE-2005-3347
    Christopher Kunz discovered that local variables get overwritten
    unconditionally in phpsysinfo, which are also present in
    egroupware, and are trusted later, which could lead to the
    inclusion of arbitrary files.
CVE-2005-3348
    Christopher Kunz discovered that user-supplied input is used
    unsanitised in phpsysinfo and imported in egroupware, causing a
    HTTP Response splitting problem.
The old stable distribution (woody) does not contain egroupware packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.0.0.007-2.dfsg-2sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-899');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your egroupware packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA899] DSA-899-1 egroupware");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-899-1 egroupware");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'egroupware', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-addressbook', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-bookmarks', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-calendar', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-comic', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-core', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-developer-tools', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-email', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-emailadmin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-etemplate', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-felamimail', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-filemanager', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-forum', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-ftp', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-fudforum', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-headlines', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-infolog', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-jinn', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-ldap', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-manual', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-messenger', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-news-admin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-phpbrain', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-phpldapadmin', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-phpsysinfo', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-polls', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-projects', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-registration', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-sitemgr', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-stocks', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-tts', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
deb_check(prefix: 'egroupware-wiki', release: '3.1', reference: '1.0.0.007-2.dfsg-2sarge4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
