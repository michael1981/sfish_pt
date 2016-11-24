# This script was automatically generated from the dsa-830
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19799);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "830");
 script_cve_id("CVE-2005-2962");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-830 security update');
 script_set_attribute(attribute: 'description', value:
'Drew Parsons noticed that the post-installation script of ntlmaps, an
NTLM authorisation proxy server, changes the permissions of the
configuration file to be world-readable.  It contains the user name
and password of the Windows NT system that ntlmaps connects to and,
hence, leaks them to local users.
The old stable distribution (woody) does not contain an ntlmaps package.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.9-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-830');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ntlmaps package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA830] DSA-830-1 ntlmaps");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-830-1 ntlmaps");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ntlmaps', release: '3.1', reference: '0.9.9-2sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
