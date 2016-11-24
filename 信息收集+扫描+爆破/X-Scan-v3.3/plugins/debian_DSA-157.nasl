# This script was automatically generated from the dsa-157
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14994);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "157");
 script_cve_id("CVE-2002-0983");
 script_bugtraq_id(5055);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-157 security update');
 script_set_attribute(attribute: 'description', value:
'The IRC client irssi is vulnerable to a denial of service condition.
The problem occurs when a user attempts to join a channel that has an
overly long topic description.  When a certain string is appended to
the topic, irssi will crash.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-157');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your irssi-text package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA157] DSA-157-1 irssi-text");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-157-1 irssi-text");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'irssi-text', release: '3.0', reference: '0.8.4-3.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
