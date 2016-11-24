# This script was automatically generated from the dsa-1401
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27630);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1401");
 script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1401 security update');
 script_set_attribute(attribute: 'description', value:
'# Translators: this is nearly a copy of DSA 1392

Several remote vulnerabilities have been discovered in the Iceape internet
suite, an unbranded version of the Seamonkey Internet Suite. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1095
    
    Michal Zalewski discovered that the unload event handler had access to
    the address of the next page to be loaded, which could allow information
    disclosure or spoofing.
    
CVE-2007-2292
    
    Stefano Di Paola discovered that insufficient validation of user names
    used in Digest authentication on a web site allows HTTP response splitting
    attacks.
    
CVE-2007-3511
    
    It was discovered that insecure focus handling of the file upload
    control can lead to information disclosure. This is a variant of
    CVE-2006-2894.
    
CVE-2007-5334
    
    Eli Friedman discovered that web pages written in Xul markup can hide the
    titlebar of windows, which can lead to spoofing attacks.
    
CVE-2007-5337
    
    Georgi Guninski discovered the insecure handling of smb:// and sftp:// URI
    schemes may lead to information disclosure. This vulnerability is only
    exploitable if Gnome-VFS support is present on the system.
    
CVE-2007-5338
    
    <q>moz_bug_r_a4</q> discovered that the protection scheme offered by XPCNativeWrappers
    could be bypassed, which might allow privilege escalation.
    
CVE-2007-5339
    
    L. David Baron, Boris Zbarsky, Georgi Guninski, Paul Nickerson, Olli Pettay,
    Jesse Ruderman, Vladimir Sukhoy, Daniel Veditz, and Martijn Wargers discovered
    crashes in the layout engine, which might allow the execution of arbitrary code.
    
CVE-2007-5340
    
    Igor Bukanov, Eli Friedman, and Jesse Ruderman discovered crashes in the
    JavaScript engine, which might allow the execution of arbitrary code.
    

The Mozilla products in the oldstable distribution (sarge) are no longer
supported with security updates.


For the stable distribution (etch) these problems have been fixed in version
1.0.11~pre071022-0etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1401');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your iceape packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1401] DSA-1401-1 iceape");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1401-1 iceape");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
