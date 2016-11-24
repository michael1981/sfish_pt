# This script was automatically generated from the dsa-426
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15263);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "426");
 script_cve_id("CVE-2003-0924");
 script_bugtraq_id(9442);
 script_xref(name: "CERT", value: "487102");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-426 security update');
 script_set_attribute(attribute: 'description', value:
'netpbm is a graphics conversion toolkit made up of a large number of
single-purpose programs.  Many of these programs were found to create
temporary files in an insecure manner, which could allow a local
attacker to overwrite files with the privileges of the user invoking a
vulnerable netpbm tool.
For the current stable distribution (woody) these problems have been
fixed in version 2:9.20-8.4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-426');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-426
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA426] DSA-426-1 netpbm-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-426-1 netpbm-free");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libnetpbm9', release: '3.0', reference: '9.20-8.4');
deb_check(prefix: 'libnetpbm9-dev', release: '3.0', reference: '9.20-8.4');
deb_check(prefix: 'netpbm', release: '3.0', reference: '9.20-8.4');
deb_check(prefix: 'netpbm-free', release: '3.0', reference: '9.20-8.4');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
