# This script was automatically generated from the dsa-1015
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22557);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1015");
 script_cve_id("CVE-2006-0058");
 script_xref(name: "CERT", value: "834865");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1015 security update');
 script_set_attribute(attribute: 'description', value:
'Mark Dowd discovered a flaw in the handling of asynchronous signals in
sendmail, a powerful, efficient, and scalable mail transport agent.
This allows a remote attacker to exploit a race condition to
execute arbitrary code as root.
For the old stable distribution (woody) this problem has been fixed in
version 8.12.3-7.2.
For the stable distribution (sarge) this problem has been fixed in
version 8.13.4-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1015');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sendmail package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1015] DSA-1015-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1015-1 sendmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmilter-dev', release: '3.0', reference: '8.12.3-7.2');
deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-7.2');
deb_check(prefix: 'sendmail-doc', release: '3.0', reference: '8.12.3-7.2');
deb_check(prefix: 'libmilter-dev', release: '3.1', reference: '8.13.4-3sarge1');
deb_check(prefix: 'libmilter0', release: '3.1', reference: '8.13.4-3sarge1');
deb_check(prefix: 'rmail', release: '3.1', reference: '8.13.4-3sarge1');
deb_check(prefix: 'sendmail', release: '3.1', reference: '8.13.4-3sarge1');
deb_check(prefix: 'sendmail-base', release: '3.1', reference: '8.13.4-3sarge1');
deb_check(prefix: 'sendmail-bin', release: '3.1', reference: '8.13.4-3sarge1');
deb_check(prefix: 'sendmail-cf', release: '3.1', reference: '8.13.4-3sarge1');
deb_check(prefix: 'sendmail-doc', release: '3.1', reference: '8.13.4-3sarge1');
deb_check(prefix: 'sensible-mda', release: '3.1', reference: '8.13.4-3sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
