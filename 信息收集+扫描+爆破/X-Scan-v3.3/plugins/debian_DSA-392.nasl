# This script was automatically generated from the dsa-392
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15229);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "392");
 script_cve_id("CVE-2003-0832", "CVE-2003-0833");
 script_bugtraq_id(8724, 8726);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-392 security update');
 script_set_attribute(attribute: 'description', value:
'Jens Steube reported two vulnerabilities in webfs, a lightweight HTTP
server for static content.
 CVE-2003-0832 - When virtual hosting is enabled, a remote client
 could specify ".." as the hostname in a request, allowing retrieval
 of directory listings or files above the document root.
 CVE-2003-0833 - A long pathname could overflow a buffer allocated on
 the stack, allowing execution of arbitrary code.  In order to exploit
 this vulnerability, it would be necessary to be able to create
 directories on the server in a location which could be accessed by
 the web server.  In conjunction with CVE-2003-0832, this could be a
 world-writable directory such as /var/tmp.
For the current stable distribution (woody) these problems have been fixed
in version 1.17.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-392');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-392
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA392] DSA-392-1 webfs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-392-1 webfs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'webfs', release: '3.0', reference: '1.17.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
