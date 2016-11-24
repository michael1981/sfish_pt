# This script was automatically generated from the dsa-399
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15236);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "399");
 script_cve_id("CVE-2003-0328");
 script_bugtraq_id(8999);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-399 security update');
 script_set_attribute(attribute: 'description', value:
'Jeremy Nelson discovered a remotely exploitable buffer overflow in
EPIC4, a popular client for Internet Relay Chat (IRC).  A malicious
server could craft a reply which triggers the client to allocate a
negative amount of memory.  This could lead to a denial of service if
the client only crashes, but may also lead to executing of arbitrary
code under the user id of the chatting user.
For the stable distribution (woody) this problem has been fixed in
version 1.1.2.20020219-2.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-399');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your epic4 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA399] DSA-399-1 epic4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-399-1 epic4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'epic4', release: '3.0', reference: '1.1.2.20020219-2.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
