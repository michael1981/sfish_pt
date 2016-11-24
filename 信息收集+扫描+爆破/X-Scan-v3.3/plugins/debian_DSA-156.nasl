# This script was automatically generated from the dsa-156
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14993);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "156");
 script_cve_id("CVE-2002-0984");
 script_bugtraq_id(5555);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-156 security update');
 script_set_attribute(attribute: 'description', value:
'All versions of the EPIC script Light prior to 2.7.30p5 (on the 2.7
branch) and prior to 2.8pre10 (on the 2.8 branch) running on any
platform are vulnerable to a remotely-exploitable bug, which can lead
to nearly arbitrary code execution.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-156');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your epic4-script-light package and
restart your IRC client.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA156] DSA-156-1 epic4-script-light");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-156-1 epic4-script-light");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'epic4-script-light', release: '3.0', reference: '2.7.30p5-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
