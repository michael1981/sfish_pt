# This script was automatically generated from the dsa-620
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16073);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "620");
 script_cve_id("CVE-2004-0452", "CVE-2004-0976");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-620 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Perl, the popular
scripting language.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Jeroen van Wolffelaar discovered that the rmtree() function in the
    File::Path module removes directory trees in an insecure manner
    which could lead to the removal of arbitrary files and directories
    through a symlink attack.
    Trustix developers discovered several insecure uses of temporary
    files in many modules which allow a local attacker to overwrite
    files via a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 5.6.1-8.8.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-620');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your perl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA620] DSA-620-1 perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-620-1 perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libcgi-fast-perl', release: '3.0', reference: '5.6.1-8.8');
deb_check(prefix: 'libperl-dev', release: '3.0', reference: '5.6.1-8.8');
deb_check(prefix: 'libperl5.6', release: '3.0', reference: '5.6.1-8.8');
deb_check(prefix: 'perl', release: '3.0', reference: '5.6.1-8.8');
deb_check(prefix: 'perl-base', release: '3.0', reference: '5.6.1-8.8');
deb_check(prefix: 'perl-debug', release: '3.0', reference: '5.6.1-8.8');
deb_check(prefix: 'perl-doc', release: '3.0', reference: '5.6.1-8.8');
deb_check(prefix: 'perl-modules', release: '3.0', reference: '5.6.1-8.8');
deb_check(prefix: 'perl-suid', release: '3.0', reference: '5.6.1-8.8');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
