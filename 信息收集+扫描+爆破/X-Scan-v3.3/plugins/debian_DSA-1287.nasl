# This script was automatically generated from the dsa-1287
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25176);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1287");
 script_cve_id("CVE-2006-7191", "CVE-2007-1840");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1287 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been identified in the version of
ldap-account-manager shipped with Debian 3.1 (sarge).
CVE-2006-7191
    An untrusted PATH vulnerability could allow a local attacker to execute
    arbitrary code with elevated privileges by providing a malicious rm
    executable and specifying a PATH environment variable referencing this
    executable.
CVE-2007-1840
    Improper escaping of HTML content could allow an attacker to execute a
    cross-site scripting attack (XSS) and execute arbitrary code in the
    victim\'s browser in the security context of the affected web site.
For the old stable distribution (sarge), this problem has been fixed in
version 0.4.9-2sarge1.  Newer versions of Debian (etch, lenny, and sid),
are not affected.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1287');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ldap-account-manager package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1287] DSA-1287-1 ldap-account-manager");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1287-1 ldap-account-manager");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ldap-account-manager', release: '3.1', reference: '0.4.9-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
