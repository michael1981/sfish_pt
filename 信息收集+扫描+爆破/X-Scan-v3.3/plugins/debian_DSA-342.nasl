# This script was automatically generated from the dsa-342
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15179);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "342");
 script_cve_id("CVE-2003-0538");
 script_bugtraq_id(8125);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-342 security update');
 script_set_attribute(attribute: 'description', value:
'mozart, a development platform based on the Oz language, includes MIME
configuration data which specifies that Oz applications should be
passed to the Oz interpreter for execution.  This means that file
managers, web browsers, and other programs which honor the mailcap
file could automatically execute Oz programs downloaded from untrusted
sources.  Thus, a malicious Oz program could execute arbitrary code
under the uid of a user running a MIME-aware client program if the
user selected a file (for example, choosing a link in a web browser).
For the stable distribution (woody) this problem has been fixed in
version 1.2.3.20011204-3woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-342');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-342
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA342] DSA-342-1 mozart");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-342-1 mozart");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozart', release: '3.0', reference: '1.2.3.20011204-3woody1');
deb_check(prefix: 'mozart-contrib', release: '3.0', reference: '1.2.3.20011204-3woody1');
deb_check(prefix: 'mozart-doc-html', release: '3.0', reference: '1.2.3.20011204-3woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
