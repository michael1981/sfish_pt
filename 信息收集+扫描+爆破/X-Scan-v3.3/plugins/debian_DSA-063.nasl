# This script was automatically generated from the dsa-063
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14900);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "063");
 script_cve_id("CVE-2001-0763", "CVE-2001-1322");
 script_bugtraq_id(2826, 2840);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-063 security update');
 script_set_attribute(attribute: 'description', value:
'zen-parse reported on bugtraq that there is a possible buffer overflow
in the logging code from xinetd. This could be triggered by using a
fake identd that returns special replies when xinetd does an ident
request. 

Another problem is that xinetd sets it umask to 0. As a result any
programs that xinetd start that are not careful with file permissions
will create world-writable files.

Both problems have been fixed in version 2.1.8.8.p3-1.1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-063');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-063
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA063] DSA-063-1 xinetd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-063-1 xinetd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xinetd', release: '2.2', reference: '2.1.8.8.p3-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
