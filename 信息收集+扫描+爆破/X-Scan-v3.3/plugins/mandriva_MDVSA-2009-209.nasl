
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40694);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:209: java-1.6.0-openjdk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:209 (java-1.6.0-openjdk).");
 script_set_attribute(attribute: "description", value: "Multiple Java OpenJDK security vulnerabilities has been identified
and fixed:
The design of the W3C XML Signature Syntax and Processing (XMLDsig)
recommendation specifies an HMAC truncation length (HMACOutputLength)
but does not require a minimum for its length, which allows attackers
to spoof HMAC-based signatures and bypass authentication by specifying
a truncation length with a small number of bits (CVE-2009-0217).
The Java Web Start framework does not properly check all application
jar files trust and this allows context-dependent attackers to
execute arbitrary code via a crafted application, related to NetX
(CVE-2009-1896).
Some variables and data structures without the final
keyword definition allows context-depend attackers to
obtain sensitive information. The target variables and
data structures are stated as follow: (1) LayoutQueue, (2)
Cursor.predefined, (3) AccessibleResourceBundle.getContents,
(4) ImageReaderSpi.STANDARD_INPUT_TYPE, (5)
ImageWriterSpi.STANDARD_OUTPUT_TYPE, (6) the imageio plugins, (7)
DnsContext.debug, (8) RmfFileReader/StandardMidiFileWriter.types,
(9) AbstractSaslImpl.logger, (10)
Synth.Region.uiToRegionMap/lowerCaseNameMap, (11) the Introspector
class and a cache of BeanInfo, and (12) JAX-WS (CVE-2009-2475).
The Java Management Extensions (JMX) implementation does not
properly enforce OpenType checks, which allows context-dependent
attackers to bypass intended access restrictions by leveraging
finalizer resurrection to obtain a reference to a privileged object
(CVE-2009-2476).
A flaw in the Xerces2 as used in OpenJDK allows remote attackers to
cause denial of service via a malformed XML input (CVE-2009-2625).
The audio system does not prevent access to java.lang.System properties
either by untrusted applets and Java Web Start applications, which
allows context-dependent attackers to obtain sensitive information
by reading these properties (CVE-2009-2670).
A flaw in the SOCKS proxy implementation allows remote attackers
to discover the user name of the account that invoked either an
untrusted applet or Java Web Start application via unspecified vectors
(CVE-2009-2671).
A flaw in the proxy mechanism implementation allows remote attackers
to bypass intended access restrictions and connect to arbitrary
sites via unspecified vectors, related to a declaration that lacks
the final keyword (CVE-2009-2673).
An integer overflow in the JPEG images parsing allows context-dependent
attackers to gain privileges via an untrusted Java Web Start
application that grants permissions to itself (CVE-2009-2674).
An integer overflow in the unpack200 utility decompression allows
context-dependent attackers to gain privileges via vectors involving
either an untrusted applet or Java Web Start application that grants
permissions to itself (CVE-2009-2675).
A flaw in the JDK13Services.getProviders grants full privileges to
instances of unspecified object types, which allows context-dependent
attackers to bypass intended access restrictions either via an
untrusted applet or application (CVE-2009-2689).
A flaw in the OpenJDK's encoder, grants read access to private
variables with unspecified names, which allows context-dependent
attackers to obtain sensitive information either via an untrusted
applet or application (CVE-2009-2690).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:209");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0217", "CVE-2009-1896", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2689", "CVE-2009-2690");
script_summary(english: "Check for the version of the java-1.6.0-openjdk package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"java-1.6.0-openjdk-1.6.0.0-0.20.b16.0.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-demo-1.6.0.0-0.20.b16.0.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-devel-1.6.0.0-0.20.b16.0.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-0.20.b16.0.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-plugin-1.6.0.0-0.20.b16.0.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-src-1.6.0.0-0.20.b16.0.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-1.6.0.0-0.20.b16.0.3mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-demo-1.6.0.0-0.20.b16.0.3mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-devel-1.6.0.0-0.20.b16.0.3mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-0.20.b16.0.3mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-plugin-1.6.0.0-0.20.b16.0.3mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-src-1.6.0.0-0.20.b16.0.3mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"java-1.6.0-openjdk-", release:"MDK2009.0")
 || rpm_exists(rpm:"java-1.6.0-openjdk-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-0217", value:TRUE);
 set_kb_item(name:"CVE-2009-1896", value:TRUE);
 set_kb_item(name:"CVE-2009-2475", value:TRUE);
 set_kb_item(name:"CVE-2009-2476", value:TRUE);
 set_kb_item(name:"CVE-2009-2625", value:TRUE);
 set_kb_item(name:"CVE-2009-2670", value:TRUE);
 set_kb_item(name:"CVE-2009-2671", value:TRUE);
 set_kb_item(name:"CVE-2009-2673", value:TRUE);
 set_kb_item(name:"CVE-2009-2674", value:TRUE);
 set_kb_item(name:"CVE-2009-2675", value:TRUE);
 set_kb_item(name:"CVE-2009-2689", value:TRUE);
 set_kb_item(name:"CVE-2009-2690", value:TRUE);
}
exit(0, "Host is not affected");
