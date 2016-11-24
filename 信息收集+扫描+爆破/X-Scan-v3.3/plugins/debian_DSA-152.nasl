# This script was automatically generated from the dsa-152
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14989);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "152");
 script_cve_id("CVE-2002-0872", "CVE-2002-0873");
 script_bugtraq_id(5451);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-152 security update');
 script_set_attribute(attribute: 'description', value:
'Current versions of l2tpd, a layer 2 tunneling client/server program,
forgot to initialize the random generator which made it vulnerable
since all generated random number were 100% guessable.  When dealing
with the size of the value in an attribute value pair, too many bytes
were able to be copied, which could lead into the vendor field being
overwritten.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-152');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your l2tpd packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA152] DSA-152-1 l2tpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-152-1 l2tpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'l2tpd', release: '3.0', reference: '0.67-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
