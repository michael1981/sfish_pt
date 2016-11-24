# This script was automatically generated from the dsa-378
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15215);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "378");
 script_cve_id("CVE-2003-0705", "CVE-2003-0706");
 script_bugtraq_id(8557, 8558);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-378 security update');
 script_set_attribute(attribute: 'description', value:
'Nicolas Boullis discovered two vulnerabilities in mah-jong, a
network-enabled game.
This vulnerability could be exploited by a remote attacker to
   execute arbitrary code with the privileges of the user running the
   mah-jong server.
This vulnerability could be exploited by a remote attacker to cause
  the mah-jong server to enter a tight loop and stop responding to
  commands.
For the stable distribution (woody) these problems have been fixed in
version 1.4-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-378');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-378
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA378] DSA-378-1 mah-jong");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-378-1 mah-jong");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mah-jong', release: '3.0', reference: '1.4-2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
