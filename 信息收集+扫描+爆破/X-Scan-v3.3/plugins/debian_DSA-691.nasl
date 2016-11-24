# This script was automatically generated from the dsa-691
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17286);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "691");
 script_cve_id("CVE-2005-0098", "CVE-2005-0099");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-691 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in abuse, the SDL port of
the Abuse action game.  The Common Vulnerabilities and Exposures
project identifies the following problems:
    Erik Sjölund discovered several buffer overflows in the command line
    handling, which could lead to the execution of arbitrary code with
    elevated privileges since it is installed setuid root.
    Steve Kemp discovered that abuse creates some files without
    dropping privileges first, which may lead to the creation and
    overwriting of arbitrary files.
For the stable distribution (woody) these problems have been fixed in
version 2.00+-3woody4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-691');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your abuse package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA691] DSA-691-1 abuse");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-691-1 abuse");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'abuse', release: '3.0', reference: '2.00+-3woody4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
