# This script was automatically generated from the dsa-1403
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27842);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1403");
 script_cve_id("CVE-2007-5386", "CVE-2007-5589");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1403 security update');
 script_set_attribute(attribute: 'description', value:
'Omer Singer of the DigiTrust Group discovered several vulnerabilities in
phpMyAdmin, an application to administrate MySQL over the WWW. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-5589
    phpMyAdmin allows a remote attacker to inject arbitrary web script
    or HTML in the context of a logged in user\'s session (cross site
    scripting).
CVE-2007-5386
    phpMyAdmin, when accessed by a browser that does not URL-encode
    requests, allows remote attackers to inject arbitrary web script
    or HTML via the query string.
For the old stable distribution (sarge) this problem has been fixed in
version 4:2.6.2-3sarge6.
For the stable distribution (etch) this problem has been fixed in
version 4:2.9.1.1-6.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1403');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpmyadmin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1403] DSA-1403-1 phpmyadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1403-1 phpmyadmin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpmyadmin', release: '3.1', reference: '2.6.2-3sarge6');
deb_check(prefix: 'phpmyadmin', release: '4.0', reference: '2.9.1.1-6');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
