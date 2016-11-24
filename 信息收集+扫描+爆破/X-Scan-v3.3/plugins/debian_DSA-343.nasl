# This script was automatically generated from the dsa-343
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15180);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "343");
 script_cve_id("CVE-2003-0539");
 script_bugtraq_id(8144);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-343 security update');
 script_set_attribute(attribute: 'description', value:
'skk (Simple Kana to Kanji conversion program), does not take
appropriate security precautions when creating temporary files.  This
bug could potentially be exploited to overwrite arbitrary files with
the privileges of the user running Emacs and skk.
ddskk is derived from the same code, and contains the same bug.
For the stable distribution (woody) this problem has been fixed in
skk version 10.62a-4woody1 and ddskk version 11.6.rel.0-2woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-343');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-343
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA343] DSA-343-1 skk, ddskk");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-343-1 skk, ddskk");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ddskk', release: '3.0', reference: '11.6.rel.0-2woody1');
deb_check(prefix: 'skk', release: '3.0', reference: '10.62a-4woody1');
deb_check(prefix: 'skkserv', release: '3.0', reference: '10.62a-4woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
