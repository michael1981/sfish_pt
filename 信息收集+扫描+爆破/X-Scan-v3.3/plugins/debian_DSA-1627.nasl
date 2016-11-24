# This script was automatically generated from the dsa-1627
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33826);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1627");
 script_cve_id("CVE-2008-2235");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1627 security update');
 script_set_attribute(attribute: 'description', value:
'Chaskiel M Grundman discovered that opensc, a library and utilities to
handle smart cards, would initialise smart cards with the Siemens CardOS M4
card operating system without proper access rights. This allowed everyone
to change the card\'s PIN.
With this bug anyone can change a user PIN without having the PIN or PUK
or the superusers PIN or PUK. However it can not be used to figure out the
PIN. If the PIN on your card is still the same you always had, there\'s a
reasonable chance that this vulnerability has not been exploited.
This vulnerability affects only smart cards and USB crypto tokens based on
Siemens CardOS M4, and within that group only those that were initialised
with OpenSC. Users of other smart cards and USB crypto tokens, or cards
that have been initialised with some software other than OpenSC, are not
affected.
After upgrading the package, running
pkcs15-tool&nbsp;-T
will show you whether the card is fine or vulnerable. If the card is
vulnerable, you need to update the security setting using:
pkcs15-tool&nbsp;-T&nbsp;-U.
For the stable distribution (etch), this problem has been fixed in
version 0.11.1-2etch2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1627');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your opensc package and check
your card(s) with the command described above.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1627] DSA-1627-2 opensc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1627-2 opensc");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libopensc2', release: '4.0', reference: '0.11.1-2etch2');
deb_check(prefix: 'libopensc2-dbg', release: '4.0', reference: '0.11.1-2etch2');
deb_check(prefix: 'libopensc2-dev', release: '4.0', reference: '0.11.1-2etch2');
deb_check(prefix: 'mozilla-opensc', release: '4.0', reference: '0.11.1-2etch2');
deb_check(prefix: 'opensc', release: '4.0', reference: '0.11.1-2etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
