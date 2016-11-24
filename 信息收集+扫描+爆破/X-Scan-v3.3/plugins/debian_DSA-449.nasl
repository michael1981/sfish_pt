# This script was automatically generated from the dsa-449
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15286);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "449");
 script_cve_id("CVE-2004-0104", "CVE-2004-0105");
 script_bugtraq_id(9692);
 script_xref(name: "CERT", value: "513062");
 script_xref(name: "CERT", value: "518518");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-449 security update');
 script_set_attribute(attribute: 'description', value:
'Ulf Härnhammar discovered two format string bugs (CVE-2004-0104) and
two buffer overflow bugs (CVE-2004-0105) in metamail, an
implementation of MIME.  An attacker could create a carefully-crafted
mail message which will execute arbitrary code as the victim when it
is opened and parsed through metamail.
We have been devoting some effort to trying to avoid shipping metamail
in the future.  It became unmaintainable and these are probably not
the last of the vulnerabilities.
For the stable distribution (woody) these problems have been fixed in
version 2.7-45woody.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-449');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your metamail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA449] DSA-449-1 metamail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-449-1 metamail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'metamail', release: '3.0', reference: '2.7-45woody.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
