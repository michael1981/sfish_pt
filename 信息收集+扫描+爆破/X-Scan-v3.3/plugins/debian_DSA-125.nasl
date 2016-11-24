# This script was automatically generated from the dsa-125
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14962);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "125");
 script_cve_id("CVE-2002-0166");
 script_bugtraq_id(4389);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-125 security update');
 script_set_attribute(attribute: 'description', value:
'Yuji Takahashi discovered a bug in analog which allows a cross-site
scripting type attack.  It is easy for an attacker to insert arbitrary
strings into any web server logfile.  If these strings are then
analysed by analog, they can appear in the report.  By this means an
attacker can introduce arbitrary Javascript code, for example, into an
analog report produced by someone else and read by a third person.
Analog already attempted to encode unsafe characters to avoid this
type of attack, but the conversion was incomplete.
This problem has been fixed in the upstream version 5.22 of analog.
Unfortunately patching the old version of analog in the stable
distribution of Debian instead is a very large job that defeats us.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-125');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your analog package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA125] DSA-125-1 analog");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-125-1 analog");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'analog', release: '2.2', reference: '5.22-0potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
