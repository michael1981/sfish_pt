# This script was automatically generated from the dsa-494
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15331);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "494");
 script_cve_id("CVE-2004-0408");
 script_bugtraq_id(10192);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-494 security update');
 script_set_attribute(attribute: 'description', value:
'Jack <"jack@rapturesecurity.org"> discovered a buffer overflow in
ident2, an implementation of the ident protocol (RFC1413), where a
buffer in the child_service function was slightly too small to hold
all of the data which could be written into it.  This vulnerability
could be exploited by a remote attacker to execute arbitrary code with
the privileges of the ident2 daemon (by default, the "identd" user).
For the current stable distribution (woody) this problem has been
fixed in version 1.03-3woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-494');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-494
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA494] DSA-494-1 ident2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-494-1 ident2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ident2', release: '3.0', reference: '1.03-3woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
