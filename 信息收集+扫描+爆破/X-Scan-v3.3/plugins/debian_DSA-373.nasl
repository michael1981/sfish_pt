# This script was automatically generated from the dsa-373
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15210);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "373");
 script_cve_id("CVE-2003-0654");
 script_bugtraq_id(8436);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-373 security update');
 script_set_attribute(attribute: 'description', value:
'Christian Jaeger discovered a buffer overflow in autorespond, an email
autoresponder used with qmail.  This vulnerability could potentially
be exploited by a remote attacker to gain the privileges of a user who
has configured qmail to forward messages to autorespond.  This
vulnerability is currently not believed to be exploitable due to
incidental limits on the length of the problematic input, but there
may be situations in which these limits do not apply.
For the stable distribution (woody) this problem has been fixed in
version 2.0.2-2woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-373');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-373
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA373] DSA-373-1 autorespond");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-373-1 autorespond");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'autorespond', release: '3.0', reference: '2.0.2-2woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
