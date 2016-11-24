# This script was automatically generated from the dsa-1642
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34255);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1642");
 script_cve_id("CVE-2008-3823");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1642 security update');
 script_set_attribute(attribute: 'description', value:
'Will Drewry discovered that Horde allows remote attackers to send
an email with a crafted MIME attachment filename attribute to perform
cross site scripting.
For the stable distribution (etch), this problem has been fixed in
version 3.1.3-4etch4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1642');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your horde3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1642] DSA-1642-1 horde3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1642-1 horde3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'horde3', release: '4.0', reference: '3.1.3-4etch4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
