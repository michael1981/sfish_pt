# This script was automatically generated from the dsa-176
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15013);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "176");
 script_cve_id("CVE-2002-0838");
 script_bugtraq_id(5808);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-176 security update');
 script_set_attribute(attribute: 'description', value:
'Zen-parse discovered a buffer overflow in gv, a PostScript and PDF
viewer for X11.  This problem is triggered by scanning the PostScript
file and can be exploited by an attacker sending a malformed
PostScript or PDF file.  The attacker is able to cause arbitrary code
to be run with the privileges of the victim.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-176');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gv package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA176] DSA-176-1 gv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-176-1 gv");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gv', release: '2.2', reference: '3.5.8-17.1');
deb_check(prefix: 'gv', release: '3.0', reference: '3.5.8-26.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
