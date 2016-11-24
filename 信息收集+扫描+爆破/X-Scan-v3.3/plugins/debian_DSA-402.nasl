# This script was automatically generated from the dsa-402
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15239);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "402");
 script_cve_id("CVE-2003-0902");
 script_bugtraq_id(9049);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-402 security update');
 script_set_attribute(attribute: 'description', value:
'A security-related problem has been discovered in minimalist, a
mailing list manager, which allows a remote attacker to execute
arbitrary commands.
For the stable distribution (woody) this problem has been fixed in
version 2.2-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-402');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your minimalist package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA402] DSA-402-1 minimalist");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-402-1 minimalist");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'minimalist', release: '3.0', reference: '2.2-4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
