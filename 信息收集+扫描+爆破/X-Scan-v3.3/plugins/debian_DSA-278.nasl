# This script was automatically generated from the dsa-278
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15115);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "278");
 script_cve_id("CVE-2003-0161");
 script_bugtraq_id(7230);
 script_xref(name: "CERT", value: "897604");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-278 security update');
 script_set_attribute(attribute: 'description', value:
'Michal Zalewski discovered a buffer overflow, triggered by a char to
int conversion, in the address parsing code in sendmail, a widely used
powerful, efficient, and scalable mail transport agent.  This problem
is potentially remotely exploitable.
For the stable distribution (woody) this problem has been
fixed in version 8.12.3-6.3.
For the old stable distribution (potato) this problem has been
fixed in version 8.9.3-26.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-278');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sendmail packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA278] DSA-278-1 sendmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-278-1 sendmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sendmail', release: '2.2', reference: '8.9.3-26');
deb_check(prefix: 'libmilter-dev', release: '3.0', reference: '8.12.3-6.3');
deb_check(prefix: 'sendmail', release: '3.0', reference: '8.12.3-6.3');
deb_check(prefix: 'sendmail-doc', release: '3.0', reference: '8.12.3-6.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
