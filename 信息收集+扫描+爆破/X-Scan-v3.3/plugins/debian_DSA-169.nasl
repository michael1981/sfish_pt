# This script was automatically generated from the dsa-169
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15006);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "169");
 script_cve_id("CVE-2002-1195");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-169 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar
discovered a problem in ht://Check\'s PHP interface.
The PHP interface displays information unchecked which was gathered
from crawled external web servers.  This could lead into a cross site
scripting attack if somebody has control over the server responses of
a remote web server which is crawled by ht://Check.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-169');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your htcheck package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA169] DSA-169-1 htcheck");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-169-1 htcheck");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'htcheck', release: '3.0', reference: '1.1-1.1');
deb_check(prefix: 'htcheck-php', release: '3.0', reference: '1.1-1.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
