# This script was automatically generated from the dsa-017
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14854);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "017");
 script_cve_id("CVE-2001-0110");
 script_bugtraq_id(2209);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-017 security update');
 script_set_attribute(attribute: 'description', value:
'With older versions of jazip a user could gain root
access for members of the floppy group to the local machine. The interface
doesn\'t run as root anymore and this very exploit was prevented. The program
now also truncates DISPLAY to 256 characters if it is bigger, which closes the
buffer overflow (within xforms). 
We recommend you upgrade your jazip package immediately.  
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-017');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-017
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA017] DSA-017-1 jazip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-017-1 jazip");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'jazip', release: '2.2', reference: '0.33-1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
