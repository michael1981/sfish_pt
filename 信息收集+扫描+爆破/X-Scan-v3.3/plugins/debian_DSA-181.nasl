# This script was automatically generated from the dsa-181
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15018);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "181");
 script_cve_id("CVE-2002-1157");
 script_bugtraq_id(6029);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-181 security update');
 script_set_attribute(attribute: 'description', value:
'Joe Orton discovered a cross site scripting problem in mod_ssl, an
Apache module that adds Strong cryptography (i.e. HTTPS support) to
the webserver.  The module will return the server name unescaped in
the response to an HTTP request on an SSL port.
Like the other recent Apache XSS bugs, this only affects servers using
a combination of "UseCanonicalName off" (default in the Debian package
of Apache) and wildcard DNS.  This is very unlikely to happen, though.
Apache 2.0/mod_ssl is not vulnerable since it already escapes this
HTML.
With this setting turned on, whenever Apache needs to construct a
self-referencing URL (a URL that refers back to the server the
response is coming from) it will use ServerName and Port to form a
"canonical" name.  With this setting off, Apache will use the
hostname:port that the client supplied, when possible.  This also
affects SERVER_NAME and SERVER_PORT in CGI scripts.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-181');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libapache-mod-ssl package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA181] DSA-181-1 libapache-mod-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-181-1 libapache-mod-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-ssl', release: '2.2', reference: '2.4.10-1.3.9-1potato4');
deb_check(prefix: 'libapache-mod-ssl-doc', release: '2.2', reference: '2.4.10-1.3.9-1potato4');
deb_check(prefix: 'libapache-mod-ssl', release: '3.0', reference: '2.8.9-2.1');
deb_check(prefix: 'libapache-mod-ssl-doc', release: '3.0', reference: '2.8.9-2.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
