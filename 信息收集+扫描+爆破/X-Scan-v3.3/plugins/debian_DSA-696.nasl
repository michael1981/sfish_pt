# This script was automatically generated from the dsa-696
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17600);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "696");
 script_cve_id("CVE-2005-0448");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-696 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Szabo discovered another vulnerability in the File::Path::rmtree
function of perl, the popular scripting language.  When a process is
deleting a directory tree, a different user could exploit a race
condition to create setuid binaries in this directory tree, provided
that he already had write permissions in any subdirectory of that
tree.
For the stable distribution (woody) this problem has been fixed in
version 5.6.1-8.9.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-696');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your perl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA696] DSA-696-1 perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-696-1 perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libcgi-fast-perl', release: '3.0', reference: '5.6.1-8.9');
deb_check(prefix: 'libperl-dev', release: '3.0', reference: '5.6.1-8.9');
deb_check(prefix: 'libperl5.6', release: '3.0', reference: '5.6.1-8.9');
deb_check(prefix: 'perl', release: '3.0', reference: '5.6.1-8.9');
deb_check(prefix: 'perl-base', release: '3.0', reference: '5.6.1-8.9');
deb_check(prefix: 'perl-debug', release: '3.0', reference: '5.6.1-8.9');
deb_check(prefix: 'perl-doc', release: '3.0', reference: '5.6.1-8.9');
deb_check(prefix: 'perl-modules', release: '3.0', reference: '5.6.1-8.9');
deb_check(prefix: 'perl-suid', release: '3.0', reference: '5.6.1-8.9');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
