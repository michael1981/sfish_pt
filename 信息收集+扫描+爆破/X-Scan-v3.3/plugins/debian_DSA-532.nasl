# This script was automatically generated from the dsa-532
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15369);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "532");
 script_cve_id("CVE-2004-0488", "CVE-2004-0700");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-532 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities were discovered in libapache-mod-ssl:
  Stack-based buffer overflow in the
  ssl_util_uuencode_binary function in ssl_util.c for Apache mod_ssl,
  when mod_ssl is configured to trust the issuing CA, may allow remote
  attackers to execute arbitrary code via a client certificate with a
  long subject DN.
  Format string vulnerability in the ssl_log function
  in ssl_engine_log.c in mod_ssl 2.8.19 for Apache 1.3.31 may allow
  remote attackers to execute arbitrary messages via format string
  specifiers in certain log messages for HTTPS.
For the current stable distribution (woody), these problems have been
fixed in version 2.8.9-2.4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-532');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-532
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA532] DSA-532-2 libapache-mod-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-532-2 libapache-mod-ssl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-ssl', release: '3.0', reference: '2.8.9-2.4');
deb_check(prefix: 'libapache-mod-ssl-doc', release: '3.0', reference: '2.8.9-2.4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
