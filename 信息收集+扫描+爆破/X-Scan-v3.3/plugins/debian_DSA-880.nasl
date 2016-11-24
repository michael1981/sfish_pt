# This script was automatically generated from the dsa-880
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22746);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "880");
 script_cve_id("CVE-2005-2869", "CVE-2005-3300", "CVE-2005-3301");
 script_bugtraq_id(15169);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-880 security update');
 script_set_attribute(attribute: 'description', value:
'Several cross-site scripting vulnerabilities have been discovered in
phpmyadmin, a set of PHP-scripts to administrate MySQL over the WWW.
The Common Vulnerabilities and Exposures project identifies the
following problems:
    Andreas Kerber and Michal Cihar discovered several cross-site
    scripting vulnerabilities in the error page and in the cookie
    login.
CVE-2005-3300
    Stefan Esser discovered missing safety checks in grab_globals.php
    that could allow an attacker to induce phpmyadmin to include an
    arbitrary local file.
CVE-2005-3301
    Tobias Klein discovered several cross-site scripting
    vulnerabilities that could allow attackers to inject arbitrary
    HTML or client-side scripting.
The version in the old stable distribution (woody) has probably its
own flaws and is not easily fixable without a full audit and patch
session.  The easier way is to upgrade it from woody to sarge.
For the stable distribution (sarge) these problems have been fixed in
version 2.6.2-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-880');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpmyadmin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA880] DSA-880-1 phpmyadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-880-1 phpmyadmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpmyadmin', release: '3.1', reference: '2.6.2-3sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
