# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200811-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(34689);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200811-01");
 script_cve_id("CVE-2008-4195", "CVE-2008-4196", "CVE-2008-4197", "CVE-2008-4198", "CVE-2008-4199", "CVE-2008-4200", "CVE-2008-4292", "CVE-2008-4694", "CVE-2008-4695", "CVE-2008-4696", "CVE-2008-4697", "CVE-2008-4698", "CVE-2008-4794", "CVE-2008-4795");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200811-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200811-01
(Opera: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in Opera:
    Opera does not restrict the ability of a framed web page to change
    the address associated with a different frame (CVE-2008-4195).
    Chris Weber (Casaba Security) discovered a Cross-site scripting
    vulnerability (CVE-2008-4196).
    Michael A. Puls II discovered
    that Opera can produce argument strings that contain uninitialized
    memory, when processing custom shortcut and menu commands
    (CVE-2008-4197).
    Lars Kleinschmidt discovered that Opera, when
    rendering an HTTP page that has loaded an HTTPS page into a frame,
    displays a padlock icon and offers a security information dialog
    reporting a secure connection (CVE-2008-4198).
    Opera does not
    prevent use of links from web pages to feed source files on the local
    disk (CVE-2008-4199).
    Opera does not ensure that the address
    field of a news feed represents the feed\'s actual URL
    (CVE-2008-4200).
    Opera does not check the CRL override upon
    encountering a certificate that lacks a CRL (CVE-2008-4292).
    Chris (Matasano Security) reported that Opera may crash if it is
    redirected by a malicious page to a specially crafted address
    (CVE-2008-4694).
    Nate McFeters reported that Opera runs Java
    applets in the context of the local machine, if that applet has been
    cached and a page can predict the cache path for that applet and load
    it from the cache (CVE-2008-4695).
    Roberto Suggi Liverani
    (Security-Assessment.com) reported that Opera\'s History Search results
    does not escape certain constructs correctly, allowing for the
    injection of scripts into the page (CVE-2008-4696).
    David
    Bloom reported that Opera\'s Fast Forward feature incorrectly executes
    scripts from a page held in a frame in the outermost page instead of
    the page the JavaScript URL was located (CVE-2008-4697).
    David
    Bloom reported that Opera does not block some scripts when previewing a
    news feed (CVE-2008-4698).
    Opera does not correctly sanitize
    content when certain parameters are passed to Opera\'s History Search,
    allowing scripts to be injected into the History Search results page
    (CVE-2008-4794).
    Opera\'s links panel incorrectly causes
    scripts from a page held in a frame to be executed in the outermost
    page instead of the page where the URL was located
    (CVE-2008-4795).
  
Impact

    These vulnerabilties allow remote attackers to execute arbitrary code,
    to run scripts injected into Opera\'s History Search with elevated
    privileges, to inject arbitrary web script or HTML into web pages, to
    manipulate the address bar, to change Opera\'s preferences, to determine
    the validity of local filenames, to read cache files, browsing history,
    and subscribed feeds or to conduct other attacks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-9.62"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4195');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4196');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4197');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4198');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4199');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4200');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4292');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4694');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4695');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4696');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4697');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4698');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4794');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4795');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200811-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200811-01] Opera: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 9.62"), vulnerable: make_list("lt 9.62")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
