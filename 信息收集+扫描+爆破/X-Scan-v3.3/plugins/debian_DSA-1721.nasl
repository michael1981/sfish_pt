# This script was automatically generated from the dsa-1721
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35662);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1721");
 script_cve_id("CVE-2009-0360", "CVE-2009-0361");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1721 security update');
 script_set_attribute(attribute: 'description', value:
'Several local vulnerabilities have been discovered in the PAM module
for MIT Kerberos. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2009-0360
   Russ Allbery discovered that the Kerberos PAM module parsed
   configuration settings from enviromnent variables when run from a
   setuid context. This could lead to local privilege escalation if
   an attacker points a setuid program using PAM authentication to a
   Kerberos setup under her control.
CVE-2009-0361
   Derek Chan discovered that the Kerberos PAM module allows
   reinitialisation of user credentials when run from a setuid
   context, resulting in potential local denial of service by
   overwriting the credential cache file or to privilege escalation.
For the stable distribution (etch), these problems have been fixed in
version 2.6-1etch1.
For the upcoming stable distribution (lenny), these problems have been
fixed in version 3.11-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1721');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libpam-krb5 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1721] DSA-1721-1 libpam-krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1721-1 libpam-krb5");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-krb5', release: '4.0', reference: '2.6-1etch1');
deb_check(prefix: 'libpam-krb5', release: '5.0', reference: '3.11-4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
