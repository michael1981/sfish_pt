# This script was automatically generated from the dsa-199
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15036);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "199");
 script_cve_id("CVE-2002-1307");
 script_bugtraq_id(6204);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-199 security update');
 script_set_attribute(attribute: 'description', value:
'Steven Christey discovered a cross site scripting vulnerability in
mhonarc, a mail to HTML converter.  Carefully crafted message headers
can introduce cross site scripting when mhonarc is configured to
display all headers lines on the web.  However, it is often useful to
restrict the displayed header lines to To, From and Subject, in which
case the vulnerability cannot be exploited.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-199');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mhonarc package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA199] DSA-199-1 mhonarc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-199-1 mhonarc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mhonarc', release: '2.2', reference: '2.4.4-1.2');
deb_check(prefix: 'mhonarc', release: '3.0', reference: '2.5.2-1.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
