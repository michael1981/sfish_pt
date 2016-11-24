# This script was automatically generated from the dsa-395
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15232);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "395");
 script_cve_id("CVE-2003-0866");
 script_bugtraq_id(8824);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-395 security update');
 script_set_attribute(attribute: 'description', value:
'Aldrin Martoq has discovered a denial of service (DoS) vulnerability in
Apache Tomcat 4.0.x. Sending several non-HTTP requests to Tomcat\'s HTTP
connector makes Tomcat reject further requests on this port until it is
restarted.
For the current stable distribution (woody) this problem has been fixed
in version 4.0.3-3woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-395');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tomcat4 packages and restart the
tomcat server.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA395] DSA-395-1 tomcat4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-395-1 tomcat4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtomcat4-java', release: '3.0', reference: '4.0.3-3woody3');
deb_check(prefix: 'tomcat4', release: '3.0', reference: '4.0.3-3woody3');
deb_check(prefix: 'tomcat4-webapps', release: '3.0', reference: '4.0.3-3woody3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
