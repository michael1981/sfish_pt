# This script was automatically generated from the dsa-244
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15081);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "244");
 script_cve_id("CVE-2003-0037");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-244 security update');
 script_set_attribute(attribute: 'description', value:
'Dan Jacobson noticed a problem in noffle, an offline news server, that
leads to a segmentation fault.  It is not yet clear whether this
problem is exploitable.  However, if it is, a remote attacker could
trigger arbitrary code execution under the user that calls noffle,
probably news.
For the stable distribution (woody) this problem has been fixed in
version 1.0.1-1.1.
The old stable distribution (potato) does not contain a noffle
package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-244');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your noffle package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA244] DSA-244-1 noffle");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-244-1 noffle");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'noffle', release: '3.0', reference: '1.0.1-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
