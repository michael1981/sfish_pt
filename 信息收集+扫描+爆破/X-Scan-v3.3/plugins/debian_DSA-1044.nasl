# This script was automatically generated from the dsa-1044
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22586);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "1044");
 script_bugtraq_id(15773);
 script_bugtraq_id(16476);
 script_bugtraq_id(17516);
 script_xref(name: "CERT", value: "179014");
 script_xref(name: "CERT", value: "252324");
 script_xref(name: "CERT", value: "329500");
 script_xref(name: "CERT", value: "488774");
 script_xref(name: "CERT", value: "492382");
 script_xref(name: "CERT", value: "592425");
 script_xref(name: "CERT", value: "736934");
 script_xref(name: "CERT", value: "813230");
 script_xref(name: "CERT", value: "842094");
 script_xref(name: "CERT", value: "932734");
 script_xref(name: "CERT", value: "935556");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1044 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in Mozilla
Firefox.  The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities:
CVE-2005-4134
    Web pages with extremely long titles cause subsequent launches of
    the browser to appear to "hang" for up to a few minutes, or even
    crash if the computer has insufficient memory.  [MFSA-2006-03]
CVE-2006-0292
    The JavaScript interpreter does not properly dereference objects,
    which allows remote attackers to cause a denial of service or
    execute arbitrary code.  [MFSA-2006-01]
CVE-2006-0293
    The function allocation code allows attackers to cause a denial of
    service and possibly execute arbitrary code.  [MFSA-2006-01]
CVE-2006-0296
    XULDocument.persist() did not validate the attribute name,
    allowing an attacker to inject arbitrary XML and JavaScript code
    into localstore.rdf that would be read and acted upon during
    startup.  [MFSA-2006-05]
CVE-2006-0748
    An anonymous researcher for TippingPoint and the Zero Day
    Initiative reported that an invalid and nonsensical ordering of
    table-related tags can be exploited to execute arbitrary code.
    [MFSA-2006-27]
CVE-2006-0749
    A particular sequence of HTML tags can cause memory corruption
    that can be exploited to execute arbitrary code.  [MFSA-2006-18]
CVE-2006-1727
    Georgi Guninski reported two variants of using scripts in an XBL
    control to gain chrome privileges when the page is viewed under
    "Print Preview".  [MFSA-2006-25]
CVE-2006-1728
    "shutdown" discovered that the crypto.generateCRMFRequest method
    can be used to run arbitrary code with the privilege of the user
    running the browser, which could enable an attacker to install
    malware.  [MFSA-2006-24]
CVE-2006-1729
    Claus Jørgensen reported that a text input box can be pre-filled
    with a filename and then turned into a file-upload control,
    allowing a malicious website to steal any local file whose name
    they can guess.  [MFSA-2006-23]
CVE-2006-1730
    An anonymous researcher for TippingPoint and the Zero Day
    Initiative discovered an integer overflow triggered by the CSS
    letter-spacing property, which could be exploited to execute
    arbitrary code.  [MFSA-2006-22]
CVE-2006-1731
    "moz_bug_r_a4" discovered that some internal functions return
    prototypes instead of objects, which allows remote attackers to
    conduct cross-site scripting attacks.  [MFSA-2006-19]
CVE-2006-1732
    "shutdown" discovered that it is possible to bypass same-origin
    protections, allowing a malicious site to inject script into
    content from another site, which could allow the malicious page to
    steal information such as cookies or passwords from the other
    site, or perform transactions on the user\'s behalf if the user
    were already logged in.  [MFSA-2006-17]
CVE-2006-1733
    "moz_bug_r_a4" discovered that the compilation scope of privileged
    built-in XBL bindings is not fully protected from web content and
    can still be executed which could be used to execute arbitrary
    JavaScript, which could allow an attacker to install malware such
    
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1044');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Mozilla Firefox packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1044] DSA-1044-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
 script_summary(english: "DSA-1044-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge6');
deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge6');
deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge6');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
