# This script was automatically generated from the dsa-409
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15246);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "409");
 script_cve_id("CVE-2003-0914");
 script_bugtraq_id(9114);
 script_xref(name: "CERT", value: "734644");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-409 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability was discovered in BIND, a domain name server, whereby
a malicious name server could return authoritative negative responses
with a large TTL (time-to-live) value, thereby rendering a domain name
unreachable.  A successful attack would require that a vulnerable BIND
instance submit a query to a malicious nameserver. 
The bind9 package is not affected by this vulnerability.
For the current stable distribution (woody) this problem has been
fixed in version 1:8.3.3-2.0woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-409');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-409
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA409] DSA-409-1 bind");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-409-1 bind");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bind', release: '3.0', reference: '8.3.3-2.0woody2');
deb_check(prefix: 'bind-dev', release: '3.0', reference: '8.3.3-2.0woody2');
deb_check(prefix: 'bind-doc', release: '3.0', reference: '8.3.3-2.0woody2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
