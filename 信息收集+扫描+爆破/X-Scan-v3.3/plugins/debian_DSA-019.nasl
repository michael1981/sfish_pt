# This script was automatically generated from the dsa-019
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14856);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "019");
 script_cve_id("CVE-2001-0142");
 script_bugtraq_id(2184);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-019 security update');
 script_set_attribute(attribute: 'description', value:
'WireX discovered a potential temporary file race condition
in the way that squid sends out email messages notifying the administrator
about updating the program. This could lead to arbitrary files to get
overwritten. However the code would only be executed if running a very bleeding
edge release of squid, running a server whose time is set some number of months
in the past and squid is crashing. Read it as hardly to exploit. This version
also contains more upstream bugfixes wrt. dots in hostnames and improper HTML
quoting.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-019');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-019
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA019] DSA-019-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-019-1 squid");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squid', release: '2.2', reference: '2.2.5-3.1');
deb_check(prefix: 'squid-cgi', release: '2.2', reference: '2.2.5-3.1');
deb_check(prefix: 'squidclient', release: '2.2', reference: '2.2.5-3.1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
