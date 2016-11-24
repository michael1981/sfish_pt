# This script was automatically generated from the dsa-1488
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(30227);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1488");
 script_cve_id("CVE-2006-4758", "CVE-2006-6508", "CVE-2006-6839", "CVE-2006-6840", "CVE-2006-6841", "CVE-2008-0471");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1488 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in phpBB, a web
based bulletin board.  The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2008-0471
	Private messaging allowed cross site request forgery, making
	it possible to delete all private messages of a user by sending
	them to a crafted web page.
	Cross site request forgery enabled an attacker to perform various
	actions on behalf of a logged in user. (Applies to sarge only.)
CVE-2006-6840
	A negative start parameter could allow an attacker to create
	invalid output. (Applies to sarge only.)
CVE-2006-6839
	Redirection targets were not fully checked, leaving room for
	unauthorised external redirections via a phpBB forum.
	(Applies to sarge only.)
CVE-2006-4758
	An authenticated forum administrator may upload files of any
	type by using specially crafted filenames. (Applies to sarge only.)
For the old stable distribution (sarge), these problems have been
fixed in version 2.0.13+1-6sarge4.
For the stable distribution (etch), these problems have been fixed
in version 2.0.21-7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1488');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpbb2 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1488] DSA-1488-1 phpbb2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1488-1 phpbb2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13-6sarge4');
deb_check(prefix: 'phpbb2-conf-mysql', release: '3.1', reference: '2.0.13-6sarge4');
deb_check(prefix: 'phpbb2-languages', release: '3.1', reference: '2.0.13-6sarge4');
deb_check(prefix: 'phpbb2', release: '4.0', reference: '2.0.21-7');
deb_check(prefix: 'phpbb2-conf-mysql', release: '4.0', reference: '2.0.21-7');
deb_check(prefix: 'phpbb2-languages', release: '4.0', reference: '2.0.21-7');
deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13+1-6sarge4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
