# This script was automatically generated from the dsa-305
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15142);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "305");
 script_cve_id("CVE-2003-0308");
 script_bugtraq_id(7614);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-305 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Szabo discovered bugs in three scripts included in the sendmail
package where temporary files were created insecurely (expn,
checksendmail and doublebounce.pl).  These bugs could allow an
attacker to gain the privileges of a user invoking the script
(including root).
For the stable distribution (woody) these problems have been fixed in
version 8.12.3-6.4.
For the old stable distribution (potato) these problems have been fixed
in version 8.9.3-26.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-305');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-305
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA305] DSA-305-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-305-1 sendmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sendmail', release: '2.2', reference: '8.9.3-26.1');
deb_check(prefix: 'libmilter-dev', release: '3.0', reference: '8.12.3-6.4');
deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-6.4');
deb_check(prefix: 'sendmail-doc', release: '3.0', reference: '8.12.3-6.4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
