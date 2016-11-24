# This script was automatically generated from the dsa-077
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14914);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "077");
 script_cve_id("CVE-2001-0843");
 script_bugtraq_id(3354);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-077 security update');
 script_set_attribute(attribute: 'description', value:
'Vladimir Ivaschenko found a problem in squid (a popular proxy cache).
He discovered that there was a flaw in the code to handle FTP PUT
commands: when a mkdir-only request was done squid would detect
an internal error and exit. Since squid is configured to restart
itself on problems this is not a big problem.

This has been fixed in version 2.2.5-3.2. This problem is logged
as bug 233 in the squid bugtracker and will also be fixed in
future squid releases.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-077');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-077
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA077] DSA-077-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-077-1 squid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid', release: '2.2', reference: '2.2.5-3.2');
deb_check(prefix: 'squid-cgi', release: '2.2', reference: '2.2.5-3.2');
deb_check(prefix: 'squidclient', release: '2.2', reference: '2.2.5-3.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
