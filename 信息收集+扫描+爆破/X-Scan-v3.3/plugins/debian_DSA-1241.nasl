# This script was automatically generated from the dsa-1241
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23946);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1241");
 script_cve_id("CVE-2006-6142");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1241 security update');
 script_set_attribute(attribute: 'description', value:
'Martijn Brinkers discovered cross-site scripting vulnerabilities in
the mailto parameter of webmail.php, the session and delete_draft
parameters of compose.php and through a shortcoming in the magicHTML
filter. An attacker could abuse these to execute malicious JavaScript in
the user\'s webmail session. 
Also, a workaround was made for Internet Explorer <= 5: IE will attempt
to guess the MIME type of attachments based on content, not the MIME 
header sent. Attachments could fake to be a \'harmless\' JPEG, while they
were in fact HTML that Internet Explorer would render.
For the stable distribution (sarge) these problems have been fixed in
version 2:1.4.4-10.
For the upcoming stable distribution (etch) these problems have been fixed
in version 2:1.4.9a-1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1241');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your squirrelmail package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1241] DSA-1241-1 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1241-1 squirrelmail");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-10');
deb_check(prefix: 'squirrelmail', release: '4.0', reference: '1.4.9a-1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
