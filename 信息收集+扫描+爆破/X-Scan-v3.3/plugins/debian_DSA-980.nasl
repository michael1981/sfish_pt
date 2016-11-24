# This script was automatically generated from the dsa-980
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22846);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "980");
 script_cve_id("CVE-2004-2161", "CVE-2004-2162");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-980 security update');
 script_set_attribute(attribute: 'description', value:
'Joxean Koret discovered several security problems in tutos, a web-based
team organization software. The Common Vulnerabilities and Exposures Project
identifies the following problems:
CVE-2004-2161
     An SQL injection vulnerability allows the execution of SQL commands
     through the link_id parameter in file_overview.php.
CVE-2004-2162
     Cross-Site-Scripting vulnerabilities in the search function of the
     address book and in app_new.php allow the execution of web script
     code.
The old stable distribution (woody) does not contain tutos packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.1.20031017-2+1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-980');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tutos package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA980] DSA-980-1 tutos");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-980-1 tutos");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tutos', release: '3.1', reference: '1.1.20031017-2+1sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
