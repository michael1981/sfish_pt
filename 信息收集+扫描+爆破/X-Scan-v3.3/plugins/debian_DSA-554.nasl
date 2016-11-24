# This script was automatically generated from the dsa-554
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15391);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "554");
 script_cve_id("CVE-2004-0833");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-554 security update');
 script_set_attribute(attribute: 'description', value:
'Hugo Espuny discovered a problem in sendmail, a commonly used program
to deliver electronic mail.  When installing "sasl-bin" to use sasl in
connection with sendmail, the sendmail configuration script use fixed
user/pass information to initialise the sasl database.  Any spammer
with Debian systems knowledge could utilise such a sendmail
installation to relay spam.
For the stable distribution (woody) this problem has been fixed in
version 8.12.3-7.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-554');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sendmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA554] DSA-554-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-554-1 sendmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmilter-dev', release: '3.0', reference: '8.12.3-7.1');
deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-7.1');
deb_check(prefix: 'sendmail-doc', release: '3.0', reference: '8.12.3-7.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
