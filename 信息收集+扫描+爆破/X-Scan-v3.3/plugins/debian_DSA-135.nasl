# This script was automatically generated from the dsa-135
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14972);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "135");
 script_cve_id("CVE-2002-0653");
 script_bugtraq_id(5084);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-135 security update');
 script_set_attribute(attribute: 'description', value:
'The libapache-mod-ssl package provides SSL capability to the apache
webserver.
Recently, a problem has been found in the handling of .htaccess files,
allowing arbitrary code execution as the web server user (regardless of
ExecCGI / suexec settings), DoS attacks (killing off apache children), and
allowing someone to take control of apache child processes - all through
specially crafted .htaccess files.
This has been fixed in the libapache-mod-ssl_2.4.10-1.3.9-1potato2 package
(for potato), and the libapache-mod-ssl_2.8.9-2 package (for woody).
We recommend you upgrade as soon as possible.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-135');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-135
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA135] DSA-135-1 libapache-mod-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-135-1 libapache-mod-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-ssl', release: '2.2', reference: '2.4.10-1.3.9-1potato2');
deb_check(prefix: 'libapache-mod-ssl-doc', release: '2.2', reference: '2.4.10-1.3.9-1potato2');
deb_check(prefix: 'libapache-mod-ssl', release: '3.0', reference: '2.8.9-2');
deb_check(prefix: 'libapache-mod-ssl-doc', release: '3.0', reference: '2.8.9-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
