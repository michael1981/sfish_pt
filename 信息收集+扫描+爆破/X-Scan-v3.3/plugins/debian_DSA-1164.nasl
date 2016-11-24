# This script was automatically generated from the dsa-1164
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22706);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1164");
 script_cve_id("CVE-2006-4434");
 script_bugtraq_id(19714);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1164 security update');
 script_set_attribute(attribute: 'description', value:
'A programming error has been discovered in sendmail, an alternative
mail transport agent for Debian, that could allow a remote attacker to
crash the sendmail process by sending a specially crafted email
message.
Please note that in order to install this update you also need
libsasl2 library from proposed updates as outlined in DSA 1155-2.
For the stable distribution (sarge) this problem has been fixed in
version 8.13.3-3sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1164');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sendmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1164] DSA-1164-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1164-1 sendmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmilter-dev', release: '3.1', reference: '8.13.4-3sarge3');
deb_check(prefix: 'libmilter0', release: '3.1', reference: '8.13.4-3sarge3');
deb_check(prefix: 'rmail', release: '3.1', reference: '8.13.4-3sarge3');
deb_check(prefix: 'sendmail', release: '3.1', reference: '8.13.4-3sarge3');
deb_check(prefix: 'sendmail-base', release: '3.1', reference: '8.13.4-3sarge3');
deb_check(prefix: 'sendmail-bin', release: '3.1', reference: '8.13.4-3sarge3');
deb_check(prefix: 'sendmail-cf', release: '3.1', reference: '8.13.4-3sarge3');
deb_check(prefix: 'sendmail-doc', release: '3.1', reference: '8.13.4-3sarge3');
deb_check(prefix: 'sensible-mda', release: '3.1', reference: '8.13.4-3sarge3');
deb_check(prefix: 'sendmail', release: '3.1', reference: '8.13.3-3sarge3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
