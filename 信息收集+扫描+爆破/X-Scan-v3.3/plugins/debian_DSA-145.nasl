# This script was automatically generated from the dsa-145
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14982);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "145");
 script_cve_id("CVE-2002-0847");
 script_bugtraq_id(4731);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-145 security update');
 script_set_attribute(attribute: 'description', value:
'The authors of tinyproxy, a lightweight HTTP proxy, discovered a bug
in the handling of some invalid proxy requests.  Under some
circumstances, an invalid request may result in allocated memory
being freed twice.  This can potentially result in the execution of
arbitrary code.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-145');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tinyproxy package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA145] DSA-145-1 tinyproxy");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-145-1 tinyproxy");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tinyproxy', release: '3.0', reference: '1.4.3-2woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
