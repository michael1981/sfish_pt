# This script was automatically generated from the dsa-1051
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22593);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "1051");
 script_bugtraq_id(15773);
 script_bugtraq_id(16476);
 script_bugtraq_id(16770);
 script_bugtraq_id(16881);
 script_bugtraq_id(17516);
 script_xref(name: "CERT", value: "179014");
 script_xref(name: "CERT", value: "252324");
 script_xref(name: "CERT", value: "329500");
 script_xref(name: "CERT", value: "350262");
 script_xref(name: "CERT", value: "488774");
 script_xref(name: "CERT", value: "492382");
 script_xref(name: "CERT", value: "592425");
 script_xref(name: "CERT", value: "736934");
 script_xref(name: "CERT", value: "813230");
 script_xref(name: "CERT", value: "842094");
 script_xref(name: "CERT", value: "932734");
 script_xref(name: "CERT", value: "935556");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1051 security update');
 script_set_attribute(attribute: 'description', value:
'Several security related problems have been discovered in Mozilla
Thunderbird.  The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:
CVE-2005-2353
    The "run-mozilla.sh" script allows local users to create or
    overwrite arbitrary files when debugging is enabled via a symlink
    attack on temporary files.
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
CVE-2006-0884
    Georgi Guninski reports that forwarding mail in-line while using
    the default HTML "rich mail" editor will execute JavaScript
    embedded in the e-mail message with full privileges of the client.
    [MFSA-2006-21]
CVE-2006-1045
    The HTML rendering engine does not properly block external images
    from inline HTML attachments when "Block loading of remote images
    in mail messages" is enabled, which could allow remote attackers
    to obtain sensitive information.  [MFSA-2006-26]
CVE-2006-1529
    A vulnerability potentially allows remote attackers to cause a
    denial of service and possibly execute arbitrary code.  [MFSA-2006-20]
CVE-2006-1530
    A vulnerability potentially allows remote attackers to cause a
    denial of service and possibly execute arbitrary code.  [MFSA-2006-20]
CVE-2006-1531
    A vulnerability potentially allows remote attackers to cause a
    denial of service and possibly execute arbitrary code.  [MFSA-2006-20]
CVE-2006-1723
    A vulnerability potentially allows remote attackers to cause a
    denial of service and possibly execute arbitrary code.  [MFSA-2006-20]
CVE-2006-1724
    A vulnerability potentially allows remote attackers to cause a
    denial of service and possibly execute arbitrary code.  [MFSA-2006-20]
CVE-2006-1727
    Georgi Guninski reported two variants of using scripts in an XBL
    control to gain chrome privileges when the page is viewed under
    "Print Preview".  [MFSA-2006-25]
CVE-2006-1728
    "shutdown" discovered that the crypto.generateCRMFRequest method
    can be used to run arbitrary code with the privilege of the user
    running t
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1051');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your Mozilla Thunderbird packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1051] DSA-1051-1 mozilla-thunderbird");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_cve_id("CVE-2005-2353", "CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1045", "CVE-2006-1529", "CVE-2006-1530", "CVE-2006-1531", "CVE-2006-1723", "CVE-2006-1724", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1736", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
 script_summary(english: "DSA-1051-1 mozilla-thunderbird");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mozilla-thunderbird', release: '3.1', reference: '1.0.2-2.sarge1.0.8');
deb_check(prefix: 'mozilla-thunderbird-dev', release: '3.1', reference: '1.0.2-2.sarge1.0.8');
deb_check(prefix: 'mozilla-thunderbird-inspector', release: '3.1', reference: '1.0.2-2.sarge1.0.8');
deb_check(prefix: 'mozilla-thunderbird-offline', release: '3.1', reference: '1.0.2-2.sarge1.0.8');
deb_check(prefix: 'mozilla-thunderbird-typeaheadfind', release: '3.1', reference: '1.0.2-2.sarge1.0.8');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
