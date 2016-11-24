# This script was automatically generated from the dsa-541
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15378);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "541");
 script_cve_id("CVE-2004-0781");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-541 security update');
 script_set_attribute(attribute: 'description', value:
'Markus Wörle discovered a cross site scripting problem in
status-display (list.cgi) of the icecast internal webserver, an MPEG
layer III streaming server.  The UserAgent variable is not properly
html_escaped so that an attacker could cause the client to execute
arbitrary Java script commands.
For the stable distribution (woody) this problem has been fixed in
version 1.3.11-4.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-541');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your icecast-server package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA541] DSA-541-1 icecast-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-541-1 icecast-server");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'icecast-server', release: '3.0', reference: '1.3.11-4.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
