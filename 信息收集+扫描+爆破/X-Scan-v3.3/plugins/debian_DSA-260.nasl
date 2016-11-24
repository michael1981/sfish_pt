# This script was automatically generated from the dsa-260
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15097);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "260");
 script_cve_id("CVE-2003-0102");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-260 security update');
 script_set_attribute(attribute: 'description', value:
'iDEFENSE discovered a buffer overflow vulnerability in the ELF format
parsing of the "file" command, one which can be used to execute
arbitrary code with the privileges of the user running the command. The
vulnerability can be exploited by crafting a special ELF binary which is
then input to file. This could be accomplished by leaving the binary on
the file system and waiting for someone to use file to identify it, or
by passing it to a service that uses file to classify input. (For
example, some printer filters run file to determine how to process input
going to a printer.)
Fixed packages are available in version 3.28-1.potato.1 for Debian 2.2
(potato) and version 3.37-3.1.woody.1 for Debian 3.0 (woody). We
recommend you upgrade your file package immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-260');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-260
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA260] DSA-260-1 file");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-260-1 file");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'file', release: '2.2', reference: '3.28-1.potato.1');
deb_check(prefix: 'file', release: '3.0', reference: '3.37-3.1.woody.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
