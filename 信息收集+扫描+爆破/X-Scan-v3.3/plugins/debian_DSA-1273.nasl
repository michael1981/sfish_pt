# This script was automatically generated from the dsa-1273
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(24921);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1273");
 script_cve_id("CVE-2007-1543", "CVE-2007-1544", "CVE-2007-1545", "CVE-2007-1546", "CVE-2007-1547");
 script_bugtraq_id(23017);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1273 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in nas, the Network Audio
System.
CVE-2007-1543
A stack-based buffer overflow in the accept_att_local function in
server/os/connection.c in nas allows remote attackers to execute
arbitrary code via a long path slave name in a USL socket connection.
CVE-2007-1544
An integer overflow in the ProcAuWriteElement function in
server/dia/audispatch.c allows remote attackers to cause a denial of
service (crash) and possibly execute arbitrary code via a large
max_samples value.
CVE-2007-1545
The AddResource function in server/dia/resource.c allows remote
attackers to cause a denial of service (server crash) via a
nonexistent client ID.
CVE-2007-1546
An array index error allows remote attackers to cause a denial of service
(crash) via (1) large num_action values in the ProcAuSetElements
function in server/dia/audispatch.c or (2) a large inputNum parameter
to the compileInputs function in server/dia/auutil.c.
CVE-2007-1547
The ReadRequestFromClient function in server/os/io.c allows remote
attackers to cause a denial of service (crash) via multiple
simultaneous connections, which triggers a NULL pointer dereference.
For the stable distribution (sarge), these problems have been fixed in
version 1.7-2sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1273');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your nas package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1273] DSA-1273-1 nas");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1273-1 nas");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libaudio-dev', release: '3.1', reference: '1.7-2sarge1');
deb_check(prefix: 'libaudio2', release: '3.1', reference: '1.7-2sarge1');
deb_check(prefix: 'nas', release: '3.1', reference: '1.7-2sarge1');
deb_check(prefix: 'nas-bin', release: '3.1', reference: '1.7-2sarge1');
deb_check(prefix: 'nas-doc', release: '3.1', reference: '1.7-2sarge1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
