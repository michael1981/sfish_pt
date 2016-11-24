# This script was automatically generated from the dsa-800
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19570);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "800");
 script_cve_id("CVE-2005-2491");
 script_bugtraq_id(14620);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-800 security update');
 script_set_attribute(attribute: 'description', value:
'An integer overflow with subsequent buffer overflow has been detected
in PCRE, the Perl Compatible Regular Expressions library, which allows
an attacker to execute arbitrary code.
Since several packages link dynamically to this library you are
advised to restart the corresponding services or programs
respectively.  The command &ldquo;apt-cache showpkg libpcre3&rdquo; will list
the corresponding packages in the "Reverse Depends:" section.
For the old stable distribution (woody) this problem has been fixed in
version 3.4-1.1woody1.
For the stable distribution (sarge) this problem has been fixed in
version 4.5-1.2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-800');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libpcre3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA800] DSA-800-1 pcre3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-800-1 pcre3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpcre3', release: '3.0', reference: '3.4-1.1woody1');
deb_check(prefix: 'libpcre3-dev', release: '3.0', reference: '3.4-1.1woody1');
deb_check(prefix: 'pgrep', release: '3.0', reference: '3.4-1.1woody1');
deb_check(prefix: 'libpcre3', release: '3.1', reference: '4.5-1.2sarge1');
deb_check(prefix: 'libpcre3-dev', release: '3.1', reference: '4.5-1.2sarge1');
deb_check(prefix: 'pcregrep', release: '3.1', reference: '4.5-1.2sarge1');
deb_check(prefix: 'pgrep', release: '3.1', reference: '4.5-1.2sarge1');
deb_check(prefix: 'pcre3', release: '3.1', reference: '4.5-1.2sarge1');
deb_check(prefix: 'pcre3', release: '3.0', reference: '3.4-1.1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
