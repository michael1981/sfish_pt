# This script was automatically generated from the dsa-170
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15007);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "170");
 script_cve_id("CVE-2002-1148");
 script_bugtraq_id(5786);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-170 security update');
 script_set_attribute(attribute: 'description', value:
'A security vulnerability has been found in all Tomcat 4.x releases.
This problem allows an attacker to use a specially crafted URL to
return the unprocessed source code of a JSP page, or, under special
circumstances, a static resource which would otherwise have been
protected by security constraints, without the need for being properly
authenticated.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-170');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tomcat package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA170] DSA-170-1 tomcat4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-170-1 tomcat4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtomcat4-java', release: '3.0', reference: '4.0.3-3woody1');
deb_check(prefix: 'tomcat4', release: '3.0', reference: '4.0.3-3woody1');
deb_check(prefix: 'tomcat4-webapps', release: '3.0', reference: '4.0.3-3woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
