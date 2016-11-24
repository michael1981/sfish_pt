# This script was automatically generated from the dsa-207
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15044);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "207");
 script_cve_id("CVE-2002-0836");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-207 security update');
 script_set_attribute(attribute: 'description', value:
'The SuSE security team discovered a vulnerability in kpathsea library
(libkpathsea) which is used by xdvi and dvips.  Both programs call the
system() function insecurely, which allows a remote attacker to
execute arbitrary commands via cleverly crafted DVI files.
If dvips is used in a print filter, this allows a local or remote
attacker with print permission execute arbitrary code as the printer
user (usually lp).
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-207');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tetex-lib package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA207] DSA-207-1 tetex-bin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-207-1 tetex-bin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tetex-bin', release: '2.2', reference: '1.0.6-7.3');
deb_check(prefix: 'tetex-dev', release: '2.2', reference: '1.0.6-7.3');
deb_check(prefix: 'tetex-lib', release: '2.2', reference: '1.0.6-7.3');
deb_check(prefix: 'libkpathsea-dev', release: '3.0', reference: '1.0.7+20011202-7.1');
deb_check(prefix: 'libkpathsea3', release: '3.0', reference: '1.0.7+20011202-7.1');
deb_check(prefix: 'tetex-bin', release: '3.0', reference: '1.0.7+20011202-7.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
