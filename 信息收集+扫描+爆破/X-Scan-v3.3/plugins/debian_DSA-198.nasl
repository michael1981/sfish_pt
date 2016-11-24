# This script was automatically generated from the dsa-198
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15035);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "198");
 script_cve_id("CVE-2002-1313");
 script_bugtraq_id(6193);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-198 security update');
 script_set_attribute(attribute: 'description', value:
'A problem has been discovered in nullmailer, a simple relay-only mail
transport agent for hosts that relay mail to a fixed set of smart
relays.  When a mail is to be delivered locally to a user that doesn\'t
exist, nullmailer tries to deliver it, discovers a user unknown error
and stops delivering.  Unfortunately, it stops delivering entirely,
not only this mail.  Hence, it\'s very easy to craft a denial of service.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-198');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your nullmailer package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA198] DSA-198-1 nullmailer");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-198-1 nullmailer");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nullmailer', release: '3.0', reference: '1.00RC5-16.1woody2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
