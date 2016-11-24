# This script was automatically generated from the dsa-903
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22769);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "903");
 script_cve_id("CVE-2005-2475");
 script_bugtraq_id(14450);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-903 security update');
 script_set_attribute(attribute: 'description', value:
'The unzip update in DSA 903 contained a regression so that symbolic
links that are resolved later in a zip archive aren\'t supported
anymore.  This update corrects this behaviour.  For completeness,
below please find the original advisory text:
Imran Ghory discovered a race condition in the permissions setting
code in unzip.  When decompressing a file in a directory an attacker
has access to, unzip could be tricked to set the file permissions to a
different file the user has permissions to.
For the old stable distribution (woody) this problem has been fixed in
version 5.50-1woody5.
For the stable distribution (sarge) this problem has been fixed in
version 5.52-1sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-903');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your unzip package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA903] DSA-903-2 unzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-903-2 unzip");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'unzip', release: '3.0', reference: '5.50-1woody5');
deb_check(prefix: 'unzip', release: '3.1', reference: '5.52-1sarge3');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
