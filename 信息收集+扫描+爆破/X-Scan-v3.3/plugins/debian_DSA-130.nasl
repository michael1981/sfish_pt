# This script was automatically generated from the dsa-130
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14967);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "130");
 script_cve_id("CVE-2002-0353", "CVE-2002-0401", "CVE-2002-0402", "CVE-2002-0403", "CVE-2002-0404");
 script_bugtraq_id(4604, 4805, 4806, 4807, 4808);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-130 security update');
 script_set_attribute(attribute: 'description', value:
'Ethereal versions prior to 0.9.3 were vulnerable to an allocation error
in the ASN.1 parser. This can be triggered when analyzing traffic using
the SNMP, LDAP, COPS, or Kerberos protocols in ethereal. This
vulnerability was announced in the ethereal security advisory
enpa-sa-00003.
This issue has been corrected in ethereal version 0.8.0-3potato for
Debian 2.2 (potato).
Additionally, a number of vulnerabilities were discussed in ethereal
security advisory
enpa-sa-00004;
the version of ethereal in Debian 2.2
(potato) is not vulnerable to the issues raised in this later advisory.
Users of the not-yet-released woody distribution should ensure that they
are running ethereal 0.9.4-1 or a later version.
We recommend you upgrade your ethereal package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-130');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-130
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA130] DSA-130-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-130-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '2.2', reference: '0.8.0-3potato');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
