# This script was automatically generated from the dsa-196
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15033);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "196");
 script_cve_id("CVE-2002-0029", "CVE-2002-1219", "CVE-2002-1220", "CVE-2002-1221");
 script_bugtraq_id(6159, 6160, 6161);
 script_xref(name: "CERT", value: "229595");
 script_xref(name: "CERT", value: "542971");
 script_xref(name: "CERT", value: "581682");
 script_xref(name: "CERT", value: "844360");
 script_xref(name: "CERT", value: "852283");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-196 security update');
 script_set_attribute(attribute: 'description', value:
'[Bind version 9, the bind9 package, is not affected by these problems.]
ISS X-Force has discovered several serious vulnerabilities in the Berkeley
Internet Name Domain Server (BIND).  BIND is the most common implementation
of the DNS (Domain Name Service) protocol, which is used on the vast
majority of DNS servers on the Internet.  DNS is a vital Internet protocol
that maintains a database of easy-to-remember domain names (host names) and
their corresponding numerical IP addresses.
Circumstantial evidence suggests that the Internet Software Consortium
(ISC), maintainers of BIND, was made aware of these issues in mid-October.
Distributors of Open Source operating systems, including Debian, were
notified of these vulnerabilities via CERT about 12 hours before the release
of the advisories on November 12th.  This notification did not include any
details that allowed us to identify the vulnerable code, much less prepare
timely fixes.
Unfortunately ISS and the ISC released their security advisories with only
descriptions of the vulnerabilities, without any patches.  Even though there
were no signs that these exploits are known to the black-hat community, and
there were no reports of active attacks, such attacks could have been
developed in the meantime - with no fixes available.
We can all express our regret at the inability of the ironically named
Internet Software Consortium to work with the Internet community in handling
this problem.  Hopefully this will not become a model for dealing with
security issues in the future.
The Common Vulnerabilities and Exposures (CVE) project identified the
following vulnerabilities:
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-196');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bind package immediately, update to
bind9, or switch to another DNS server implementation.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA196] DSA-196-1 bind");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-196-1 bind");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bind', release: '2.2', reference: '8.2.3-0.potato.3');
deb_check(prefix: 'bind-dev', release: '2.2', reference: '8.2.3-0.potato.3');
deb_check(prefix: 'bind-doc', release: '2.2', reference: '8.2.3-0.potato.3');
deb_check(prefix: 'dnsutils', release: '2.2', reference: '8.2.3-0.potato.3');
deb_check(prefix: 'task-dns-server', release: '2.2', reference: '8.2.3-0.potato.3');
deb_check(prefix: 'bind', release: '3.0', reference: '8.3.3-2.0woody1');
deb_check(prefix: 'bind-dev', release: '3.0', reference: '8.3.3-2.0woody1');
deb_check(prefix: 'bind-doc', release: '3.0', reference: '8.3.3-2.0woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
